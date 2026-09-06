/**
 * Telegram Bot Worker v3.71
 * 架构: Cloudflare Workers + D1 Database
 *
 * ✅ P0:
 * - Webhook secret_token 校验（拒绝非 Telegram）
 * - /submit_token 强制 initData 验签（不信任 userId）
 * - 管理员鉴权 Set 精确匹配（避免 includes 子串误判）
 * - 话题创建分布式幂等（D1 抢锁）
 *
 * ✅ P1:
 * - update 幂等去重（processed_updates）
 * - 全局/单用户限流（ratelimits，使用 RETURNING 降低 round trips）
 * - TG API 重试与退避（429/5xx/网络异常）
 * - 话题轮询指数退避 + 抖动，降低 D1 压力
 *
 * ✅ P2:
 * - 正则 ReDoS 缓解：限制输入长度 + 拒绝高风险 regex 形态
 * - messages 表 TTL 清理（默认保留 30 天），异步概率触发
 *
 * ✅ 修复：
 * - 屏蔽用户不再"/start 自愈解封"；屏蔽后无法再发送消息触达管理员
 * - 新增管理员私聊命令：/reset <id> 强制用户重新验证
 *
 * ✅ v3.71 新增：
 * - 图形验证码（SVG 算式）可选开启
 * - 与 Turnstile / reCAPTCHA / 问题验证相互独立，可叠加
 * - 管理员面板新增图形验证码开关
 *
 * 需要新增环境变量：
 * - TELEGRAM_WEBHOOK_SECRET: Telegram setWebhook 的 secret_token（请求头 X-Telegram-Bot-Api-Secret-Token）
 */

// --- 1. 静态配置与常量 ---
const CACHE = {
  data: {},
  ts: 0,
  ttl: 60000,
  locks: new Set(),
  admin: {
    ts: 0,
    ttl: 60000,
    primarySet: new Set(),
    authSet: new Set()
  },
  cleanup: {
    processed_updates_ts: 0,
    ratelimits_ts: 0,
    messages_ts: 0
  }
};

const DEFAULTS = {
  welcome_msg: "欢迎 {name}！请先完成验证。",
  enable_verify: "true",
  enable_qa_verify: "true",
  captcha_mode: "turnstile",
  verif_q: "1+1=?\n提示：答案在简介中。",
  verif_a: "2",
  block_threshold: "5",
  enable_admin_receipt: "true",
  enable_image_forwarding: "true",
  enable_link_forwarding: "true",
  enable_text_forwarding: "true",
  enable_channel_forwarding: "true",
  enable_forward_forwarding: "true",
  enable_audio_forwarding: "true",
  enable_sticker_forwarding: "true",
  backup_group_id: "",
  unread_topic_id: "",
  blocked_topic_id: "",
  busy_mode: "false",
  busy_msg: "当前是非营业时间，消息已收到，管理员稍后回复。",
  block_keywords: "[]",
  keyword_responses: "[]",
  authorized_admins: "[]",
  enable_image_captcha: "false"   // ← 新增：图形验证码开关
};

const DELIVERED_REACTION = "👍";

const PROCESSED_UPDATES_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const RATELIMIT_CLEANUP_TTL_MS = 10 * 60 * 1000;
const RATELIMIT_USER_WINDOW_MS = 2000;
const RATELIMIT_USER_MAX = 6;
const RATELIMIT_GLOBAL_WINDOW_MS = 10000;
const RATELIMIT_GLOBAL_MAX = 250;
const SUBMIT_RL_WINDOW_MS = 60000;
const SUBMIT_RL_IP_MAX = 30;
const SUBMIT_RL_UID_MAX = 10;
const TOPIC_LOCK_STALE_MS = 60 * 1000;
const TOPIC_LOCK_POLL_MAX = 8;
const TOPIC_LOCK_POLL_BASE_MS = 160;
const VERIFY_NONCE_TTL_MS = 15 * 60 * 1000;
const MESSAGES_TTL_DAYS = 30;
const IMG_CAPTCHA_TTL_MS = 10 * 60 * 1000; // 图形验证码 10 分钟有效

const REGEX_MAX_PATTERN_LEN = 256;
const REGEX_MAX_TEXT_LEN = 512;
const REGEX_REJECT_PATTERNS = [
  /\([^)]*\)\s*[+*{]/,
  /\(\s*\.\*\s*\)\s*\+/,
  /\(\s*\.\+\s*\)\s*\+/,
  /\\[1-9]/,
  /\(\?<=[\s\S]*\)/,
  /\(\?<![\s\S]*\)/
];

const MSG_TYPES = [
  {
    check: m => m.forward_from || m.forward_from_chat,
    key: "enable_forward_forwarding",
    name: "转发消息",
    extra: m => (m.forward_from_chat?.type === "channel" ? "enable_channel_forwarding" : null)
  },
  { check: m => m.audio || m.voice, key: "enable_audio_forwarding", name: "语音/音频" },
  { check: m => m.sticker || m.animation, key: "enable_sticker_forwarding", name: "贴纸/GIF" },
  { check: m => m.photo || m.video || m.document, key: "enable_image_forwarding", name: "媒体文件" },
  { check: m => (m.entities || []).some(e => ["url", "text_link"].includes(e.type)), key: "enable_link_forwarding", name: "链接" },
  { check: m => m.text, key: "enable_text_forwarding", name: "纯文本" }
];

// --- 2. 核心入口 ---
export default {
  async fetch(req, env, ctx) {
    ctx.waitUntil(dbInit(env).catch(e => console.error("DB Init Failed:", e)));

    const url = new URL(req.url);

    try {
      if (req.method === "GET") {
        if (url.pathname === "/verify") return handleVerifyPage(url, env);
        if (url.pathname === "/") return new Response("Bot v3.71 (Image Captcha Support)", { status: 200 });
      }

      if (req.method === "POST") {
        if (url.pathname === "/submit_token") return handleTokenSubmit(req, env, ctx);

        if (!isTelegramWebhook(req, env)) {
          return new Response("Forbidden", { status: 403 });
        }

        try {
          const update = await req.json();
          const ok = await markUpdateOnce(update, env, ctx);
          if (!ok) return new Response("OK");
          ctx.waitUntil(handleUpdate(update, env, ctx));
          return new Response("OK");
        } catch {
          return new Response("Bad Request", { status: 400 });
        }
      }
    } catch (e) {
      console.error("Critical Worker Error:", e);
      return new Response("Internal Server Error", { status: 500 });
    }

    return new Response("404 Not Found", { status: 404 });
  }
};

// --- 3. 数据库封装 ---
const safeParse = (str, fb = {}) => {
  try { return JSON.parse(str); } catch { return fb; }
};

const sql = async (env, query, args = [], type = "run") => {
  try {
    const stmt = env.TG_BOT_DB.prepare(query).bind(...(Array.isArray(args) ? args : [args]));
    return type === "run" ? await stmt.run() : await stmt[type]();
  } catch (e) {
    console.error(`SQL Fail [${query}]:`, e);
    if (query.match(/^(INSERT|UPDATE|DELETE|REPLACE|ALTER|CREATE)/i)) throw e;
    return null;
  }
};

const tryRun = async (env, query, args = []) => {
  try {
    const stmt = env.TG_BOT_DB.prepare(query).bind(...(Array.isArray(args) ? args : [args]));
    return await stmt.run();
  } catch { return null; }
};

async function getCfg(k, env) {
  const now = Date.now();
  if (CACHE.ts && now - CACHE.ts < CACHE.ttl && CACHE.data[k] !== undefined) return CACHE.data[k];
  const rows = await sql(env, "SELECT * FROM config", [], "all");
  if (rows?.results) {
    CACHE.data = {};
    rows.results.forEach(r => (CACHE.data[r.key] = r.value));
    CACHE.ts = now;
  }
  const envK = k.toUpperCase().replace(/_MSG|_Q|_A/, m => ({ _MSG: "_MESSAGE", _Q: "_QUESTION", _A: "_ANSWER" }[m]));
  return CACHE.data[k] ?? (env[envK] || DEFAULTS[k] || "");
}

async function setCfg(k, v, env) {
  await sql(env, "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", [k, v]);
  CACHE.ts = 0;
}

async function getUser(id, env) {
  let u = await sql(env, "SELECT * FROM users WHERE user_id = ?", id, "first");
  if (!u) {
    try { await sql(env, "INSERT OR IGNORE INTO users (user_id, user_state, user_info_json) VALUES (?, 'new', ?)", [id, "{}"]); } catch {}
    u = await sql(env, "SELECT * FROM users WHERE user_id = ?", id, "first");
  }
  if (!u) {
    u = { user_id: id, user_state: "new", is_blocked: 0, block_count: 0, topic_id: null, user_info_json: "{}", topic_creating: 0, topic_create_ts: 0 };
  }
  u.is_blocked = !!u.is_blocked;
  u.user_info = safeParse(u.user_info_json, {});
  u.topic_creating = !!u.topic_creating;
  u.topic_create_ts = u.topic_create_ts || 0;
  return u;
}

async function mergeUserInfo(id, patch, env) {
  const row = await sql(env, "SELECT user_info_json FROM users WHERE user_id = ?", id, "first");
  const cur = safeParse(row?.user_info_json || "{}", {});
  const merged = { ...(cur && typeof cur === "object" ? cur : {}), ...(patch && typeof patch === "object" ? patch : {}) };
  return JSON.stringify(merged);
}

async function updUser(id, data, env) {
  if (data.user_info) {
    data.user_info_json = await mergeUserInfo(id, data.user_info, env);
    delete data.user_info;
  }
  const keys = Object.keys(data);
  if (!keys.length) return;
  const safeKeys = keys.filter(k =>
    ["user_state", "is_blocked", "block_count", "topic_id", "user_info_json", "topic_creating", "topic_create_ts"].includes(k)
  );
  if (!safeKeys.length) return;
  const q = `UPDATE users SET ${safeKeys.map(k => `${k}=?`).join(",")} WHERE user_id=?`;
  const v = [...safeKeys.map(k => (typeof data[k] === "boolean" ? (data[k] ? 1 : 0) : data[k])), id];
  try { await sql(env, q, v); } catch (e) { console.error("Update User Failed:", e); }
}

async function dbInit(env) {
  if (!env.TG_BOT_DB) return;
  await env.TG_BOT_DB.batch([
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      user_state TEXT DEFAULT 'new',
      is_blocked INTEGER DEFAULT 0,
      block_count INTEGER DEFAULT 0,
      topic_id TEXT,
      user_info_json TEXT DEFAULT '{}',
      topic_creating INTEGER DEFAULT 0,
      topic_create_ts INTEGER DEFAULT 0
    )`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS messages (
      user_id TEXT, message_id TEXT, text TEXT, date INTEGER,
      PRIMARY KEY (user_id, message_id)
    )`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_messages_date ON messages(date)`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS processed_updates (update_id TEXT PRIMARY KEY, ts INTEGER)`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_processed_updates_ts ON processed_updates(ts)`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS ratelimits (key TEXT PRIMARY KEY, ts INTEGER, count INTEGER)`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_ratelimits_ts ON ratelimits(ts)`),
    env.TG_BOT_DB.prepare(`CREATE TABLE IF NOT EXISTS admin_msgs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      message_id TEXT NOT NULL
    )`),
    env.TG_BOT_DB.prepare(`CREATE INDEX IF NOT EXISTS idx_admin_msgs_user ON admin_msgs(user_id)`)
  ]);
  await ensureUserColumns(env);
}

async function ensureUserColumns(env) {
  const info = await sql(env, "PRAGMA table_info(users)", [], "all");
  const cols = new Set((info?.results || []).map(r => r.name));
  const alters = [];
  if (!cols.has("topic_creating")) alters.push(`ALTER TABLE users ADD COLUMN topic_creating INTEGER DEFAULT 0`);
  if (!cols.has("topic_create_ts")) alters.push(`ALTER TABLE users ADD COLUMN topic_create_ts INTEGER DEFAULT 0`);
  for (const q of alters) { try { await sql(env, q); } catch {} }
}

// --- 4. Telegram API（带重试退避） ---
async function api(token, method, body) {
  const maxRetries = 3;
  const baseBackoff = [200, 500, 1200];
  const totalWaitCapMs = 10000;
  let waited = 0;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
      const d = await r.json().catch(() => null);
      if (r.status >= 500) throw new Error(`HTTP_${r.status}`);
      if (!d || !d.ok) {
        const errCode = d?.error_code || r.status || 0;
        if (errCode === 429 && attempt < maxRetries) {
          const retryAfterSec = Number(d?.parameters?.retry_after || 0);
          const delayMs = Math.min(5000, Math.max(200, (retryAfterSec ? retryAfterSec * 1000 : baseBackoff[attempt] || 1200)));
          if (waited + delayMs > totalWaitCapMs) break;
          waited += delayMs;
          await sleep(delayMs);
          continue;
        }
        const desc = d?.description || `TG API Error (${errCode})`;
        if (method !== "setMessageReaction") console.warn(`TG API Error [${method}]:`, desc);
        throw new Error(desc);
      }
      return d.result;
    } catch (e) {
      if (attempt < maxRetries) {
        const delayMs = baseBackoff[attempt] || 1200;
        if (waited + delayMs > totalWaitCapMs) break;
        waited += delayMs;
        await sleep(delayMs);
        continue;
      }
      if (method !== "setMessageReaction") console.warn(`TG API Fail [${method}]:`, e?.message || e);
      throw e;
    }
  }
  throw new Error(`TG API Retry Exhausted: ${method}`);
}

// --- 5. Webhook 校验 / 幂等 / 限流 / 清理 ---
function isTelegramWebhook(req, env) {
  const secret = (env.TELEGRAM_WEBHOOK_SECRET || "").toString();
  if (!secret) return false;
  const hdr = req.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  return timingSafeEqualStr(hdr, secret);
}

function safeWaitUntil(ctx, p) {
  try {
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(p);
    else p.catch(() => {});
  } catch { try { p.catch(() => {}); } catch {} }
}

function maybeCleanup(ctx, key, fn, minIntervalMs) {
  const now = Date.now();
  const last = CACHE.cleanup[key] || 0;
  if (now - last < minIntervalMs) return;
  CACHE.cleanup[key] = now;
  safeWaitUntil(ctx, fn());
}

async function markUpdateOnce(update, env, ctx) {
  try {
    const uid = (update && (update.update_id ?? update.updateId))?.toString();
    if (!uid) return true;
    const now = Date.now();
    const res = await tryRun(env, "INSERT OR IGNORE INTO processed_updates (update_id, ts) VALUES (?,?)", [uid, now]);
    const changes = res?.meta?.changes ?? res?.changes ?? 0;
    if (!changes) return false;
    if ((now % 97) === 7) {
      maybeCleanup(ctx, "processed_updates_ts", async () => {
        const cutoff = now - PROCESSED_UPDATES_TTL_MS;
        await sql(env, "DELETE FROM processed_updates WHERE ts < ?", cutoff);
      }, 60_000);
    }
    return true;
  } catch { return true; }
}

async function bumpRateKey(env, key, now) {
  const q = `
    INSERT INTO ratelimits (key, ts, count) VALUES (?, ?, 1)
    ON CONFLICT(key) DO UPDATE SET count = ratelimits.count + 1, ts = excluded.ts
    RETURNING count
  `;
  const row = await sql(env, q, [key, now], "first");
  return Number(row?.count || 0);
}

async function checkRateLimit(userId, env, ctx) {
  const now = Date.now();
  const uid = userId?.toString() || "";
  if (!uid) return { allowed: true, retryAfterMs: 0 };
  const userBucket = Math.floor(now / RATELIMIT_USER_WINDOW_MS);
  const globalBucket = Math.floor(now / RATELIMIT_GLOBAL_WINDOW_MS);
  const [uc, gc] = await Promise.all([
    bumpRateKey(env, `u:${uid}:${userBucket}`, now),
    bumpRateKey(env, `g:${globalBucket}`, now)
  ]);
  if ((now % 101) === 13) {
    maybeCleanup(ctx, "ratelimits_ts", async () => {
      await sql(env, "DELETE FROM ratelimits WHERE ts < ?", now - RATELIMIT_CLEANUP_TTL_MS);
    }, 60_000);
  }
  if (gc > RATELIMIT_GLOBAL_MAX) return { allowed: false, retryAfterMs: RATELIMIT_GLOBAL_WINDOW_MS };
  if (uc > RATELIMIT_USER_MAX) return { allowed: false, retryAfterMs: RATELIMIT_USER_WINDOW_MS };
  return { allowed: true, retryAfterMs: 0 };
}

async function checkSubmitRateLimit(req, env, ctx, uidMaybe) {
  const now = Date.now();
  const ip = (req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "").split(",")[0].trim() || "0.0.0.0";
  const bucket = Math.floor(now / SUBMIT_RL_WINDOW_MS);
  const ipCount = await bumpRateKey(env, `s:ip:${ip}:${bucket}`, now);
  if (ipCount > SUBMIT_RL_IP_MAX) return { allowed: false, reason: "ip" };
  if (uidMaybe) {
    const uCount = await bumpRateKey(env, `s:u:${uidMaybe}:${bucket}`, now);
    if (uCount > SUBMIT_RL_UID_MAX) return { allowed: false, reason: "uid" };
  }
  if ((now % 103) === 19) {
    maybeCleanup(ctx, "ratelimits_ts", async () => {
      await sql(env, "DELETE FROM ratelimits WHERE ts < ?", now - RATELIMIT_CLEANUP_TTL_MS);
    }, 60_000);
  }
  return { allowed: true };
}

function maybeCleanupMessages(env, ctx) {
  const now = Date.now();
  if ((now % 131) !== 11) return;
  maybeCleanup(ctx, "messages_ts", async () => {
    const cutoffSec = Math.floor(now / 1000) - MESSAGES_TTL_DAYS * 86400;
    await sql(env, "DELETE FROM messages WHERE date < ?", cutoffSec);
  }, 10 * 60_000);
}

// --- 6. 主 update 分发 ---
async function handleUpdate(update, env, ctx) {
  const msg = update.message || update.edited_message;
  if (!msg) return update.callback_query ? handleCallback(update.callback_query, env) : null;
  if (update.edited_message && msg.chat.type === "private") return handleEdit(msg, env);

  // 话题关闭 → 批量撤回 bot 发给用户的消息
  if (msg.forum_topic_closed && msg.chat.id.toString() === env.ADMIN_GROUP_ID && msg.message_thread_id) {
    return handleTopicClose(msg, env);
  }

  if (msg.chat.type === "private") await handlePrivate(msg, env, ctx);
  else if (msg.chat.id.toString() === env.ADMIN_GROUP_ID) await handleAdminReply(msg, env);
}

// --- 6b. 话题关闭 → 批量撤回 ---
async function handleTopicClose(msg, env) {
  const tid = msg.message_thread_id.toString();
  const u = await sql(env, "SELECT user_id FROM users WHERE topic_id = ?", tid, "first");
  if (!u?.user_id) return;
  const uid = u.user_id;

  // 查出所有 bot 曾发给该用户的消息
  const rows = await sql(env, "SELECT message_id FROM admin_msgs WHERE user_id = ?", uid, "all");
  const msgIds = (rows?.results || []).map(r => r.message_id);

  // 逐条尝试删除（bot 48h 内可删，超时则忽略）
  for (const mid of msgIds) {
    await api(env.BOT_TOKEN, "deleteMessage", { chat_id: uid, message_id: parseInt(mid) }).catch(() => {});
  }

  // 清除记录 & 重置 topic_id，让用户下次联系时重建话题
  await sql(env, "DELETE FROM admin_msgs WHERE user_id = ?", uid);
  await updUser(uid, { topic_id: null }, env);
}


function parseIdsToSet(str) {
  return new Set(
    (str || "").toString().split(/[,，]/).map(s => s.trim()).filter(Boolean)
  );
}

async function getAdminSets(env) {
  const now = Date.now();
  if (CACHE.admin.ts && now - CACHE.admin.ts < CACHE.admin.ttl && CACHE.admin.primarySet.size) {
    return { primary: CACHE.admin.primarySet, auth: CACHE.admin.authSet };
  }
  const primary = parseIdsToSet(env.ADMIN_IDS || "");
  const authList = await getJsonCfg("authorized_admins", env);
  const auth = new Set([...primary, ...((Array.isArray(authList) ? authList : []).map(x => x.toString()))]);
  CACHE.admin.ts = now;
  CACHE.admin.primarySet = primary;
  CACHE.admin.authSet = auth;
  return { primary, auth };
}

async function isPrimaryAdmin(id, env) {
  const sets = await getAdminSets(env);
  return sets.primary.has(id.toString());
}

async function isAuthAdmin(id, env) {
  const sets = await getAdminSets(env);
  return sets.auth.has(id.toString());
}

// --- 8. 私聊处理 ---
async function handlePrivate(msg, env, ctx) {
  const id = msg.chat.id.toString();
  const text = msg.text || "";
  const isStart = text.startsWith("/start");

  const u0 = await getUser(id, env);
  if (u0.is_blocked && !(await isAuthAdmin(id, env))) {
    const bk = `blocked_notice:${id}`;
    if (!CACHE.locks.has(bk)) {
      CACHE.locks.add(bk);
      setTimeout(() => CACHE.locks.delete(bk), 10000);
      api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🚫 您已被管理员屏蔽，无法发送消息。如有误判请联系管理员解除。" }).catch(() => {});
    }
    return;
  }

  if (!(await isAuthAdmin(id, env))) {
    const rl = await checkRateLimit(id, env, ctx);
    if (!rl.allowed) {
      const warnKey = `rlwarn:${id}`;
      if (!CACHE.locks.has(warnKey)) {
        CACHE.locks.add(warnKey);
        setTimeout(() => CACHE.locks.delete(warnKey), 10000);
        api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "⏳ 请求过于频繁，请稍后再试。" }).catch(() => {});
      }
      return;
    }
  }

  if (text.startsWith("/reset") && (await isPrimaryAdmin(id, env))) {
    const parts = text.trim().split(/\s+/);
    const target = (parts[1] || "").trim();
    if (!target || !/^\d+$/.test(target)) {
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "用法：/reset <user_id>\n示例：/reset 123456789" });
    }
    await forceResetUserVerify(target, env);
    api(env.BOT_TOKEN, "sendMessage", { chat_id: target, text: "⚠️ 管理员要求您重新验证。\n请发送 /start 重新完成验证流程。" }).catch(() => {});
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `✅ 已重置用户 ${target} 的验证状态。` });
  }

  if (text.startsWith("/recall") && (await isAuthAdmin(id, env))) {
    const parts = text.trim().split(/\s+/);
    const target = (parts[1] || "").trim();
    if (!target || !/^\d+$/.test(target)) {
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "用法：/recall <user_id>\n示例：/recall 123456789\n\n将撤回 bot 发给该用户的所有消息。" });
    }
    const rows = await sql(env, "SELECT message_id FROM admin_msgs WHERE user_id = ?", target, "all");
    const msgIds = (rows?.results || []).map(r => r.message_id);
    if (!msgIds.length) {
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `ℹ️ 用户 ${target} 没有可撤回的消息记录。` });
    }
    let deleted = 0, failed = 0;
    for (const mid of msgIds) {
      const ok = await api(env.BOT_TOKEN, "deleteMessage", { chat_id: target, message_id: parseInt(mid) }).then(() => true).catch(() => false);
      ok ? deleted++ : failed++;
    }
    await sql(env, "DELETE FROM admin_msgs WHERE user_id = ?", target);
    await updUser(target, { topic_id: null }, env);
    return api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: `✅ 撤回完成\n用户：<code>${target}</code>\n成功：${deleted} 条 / 失败：${failed} 条（超 48h 无法删除）\n话题已重置，用户下次发消息将建新话题。`,
      parse_mode: "HTML"
    });
  }

  if (isStart) {
    if (await isPrimaryAdmin(id, env)) {
      if (ctx) ctx.waitUntil(registerCommands(env));
      return handleAdminConfig(id, null, "menu", null, null, env);
    }
  }

  if (text === "/help" && (await isAuthAdmin(id, env))) {
    return api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: "ℹ️ <b>帮助</b>\n• 回复消息即对话\n• /start 打开面板\n• /reset <id> 重置用户验证(仅主管理员)",
      parse_mode: "HTML"
    });
  }

  const u = u0;
  if (await isAuthAdmin(id, env)) {
    if (u.user_state !== "verified") await updUser(id, { user_state: "verified" }, env);
  }

  if (await isPrimaryAdmin(id, env)) {
    const stateStr = await getCfg(`admin_state:${id}`, env);
    if (stateStr) {
      const state = safeParse(stateStr);
      if (state.action === "input") return handleAdminInput(id, msg, state, env);
    }
  }

  const verifyOn = await getBool("enable_verify", env);
  const qaOn = await getBool("enable_qa_verify", env);
  const imgCaptchaOn = await getBool("enable_image_captcha", env);

  if (u.user_state !== "verified" && (verifyOn || qaOn || imgCaptchaOn)) {
    if (u.user_state === "pending_verification" && text) return verifyAnswer(id, text, env);
    // 当外部验证（Turnstile/图形）已完成，状态流转为 pending_qa 时，允许回答问题验证
    if (u.user_state === "pending_qa" && text) return verifyAnswer(id, text, env);
    // 避免重复发送欢迎语：如果用户已处于等待验证状态（非 new），不重复触发 sendStart
    if (u.user_state !== "new") return;
    return sendStart(id, msg, env);
  }

  if (isStart) {
    await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: u.topic_id
        ? "✅ <b>会话已连接</b>\n您可以直接发送消息，管理员会收到。"
        : "✅ 已验证。\n请直接发送消息以联系管理员。",
      parse_mode: "HTML"
    });
    return;
  }

  await handleVerifiedMsg(msg, u, env, ctx);
}

async function forceResetUserVerify(userId, env) {
  const uid = userId.toString();
  await updUser(uid, { user_state: "new", user_info: { verify_nonce: "", verify_nonce_ts: 0 } }, env);
}

// --- 9. Start 流程 ---
async function sendStart(id, msg, env) {
  const u = await getUser(id, env);
  if (u.is_blocked && !(await isAuthAdmin(id, env))) {
    return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🚫 您已被管理员屏蔽，无法使用本 Bot。" }).catch(() => {});
  }
  if (u.user_state === "verified") {
    await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: u.topic_id ? "✅ <b>会话已连接</b>\n您可以直接发送消息，管理员会收到。" : "✅ 已验证。\n请直接发送消息以联系管理员。",
      parse_mode: "HTML"
    });
    return;
  }

  let welcomeRaw = await getCfg("welcome_msg", env);
  const name = escapeHTML(msg.from.first_name || "User");
  let media = null, txt = welcomeRaw;
  try {
    if (welcomeRaw.trim().startsWith("{")) {
      media = safeParse(welcomeRaw, null);
      if (media) txt = media.caption || "";
    }
  } catch {}
  txt = txt.replace(/{name}|{user}/g, name);

  if (media && media.type) {
    try {
      await api(env.BOT_TOKEN, `send${media.type.charAt(0).toUpperCase() + media.type.slice(1)}`, {
        chat_id: id, [media.type]: media.file_id, caption: txt, parse_mode: "HTML"
      });
    } catch {
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: txt, parse_mode: "HTML" });
    }
  } else {
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: txt, parse_mode: "HTML" });
  }

  const url = (env.WORKER_URL || "").replace(/\/$/, "");
  const vOn = await getBool("enable_verify", env);
  const qaOn = await getBool("enable_qa_verify", env);

  const imgCaptchaOn = await getBool("enable_image_captcha", env);

  if ((vOn || imgCaptchaOn) && url) {
    const nonce = genNonce(24);
    const now = Date.now();
    await updUser(id, { user_state: "pending_turnstile", user_info: { verify_nonce: nonce, verify_nonce_ts: now } }, env);
    const verifyLink = `${url}/verify?user_id=${encodeURIComponent(id)}&nonce=${encodeURIComponent(nonce)}`;
    await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: `🛡️ <b>安全验证</b>\n请点击下方按鈕完成人机验证以继续。`,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[{
          text: "🔐 点击进行验证",
          web_app: { url: verifyLink }
        }]]
      }
    });
  } else if (qaOn) {
    await updUser(id, { user_state: "pending_verification" }, env);
    await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: id,
      text: "<b>安全提问</b>\n" + (await getCfg("verif_q", env)),
      parse_mode: "HTML"
    });
  } else {
    await updUser(id, { user_state: "verified" }, env);
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "✅ 已验证。\n请直接发送消息以联系管理员。" });
  }
}

// --- 10. 已验证用户逻辑 ---
async function handleVerifiedMsg(msg, u, env, ctx) {
  const id = u.user_id;
  if (u.is_blocked && !(await isAuthAdmin(id, env))) return;
  const text = msg.text || msg.caption || "";

  if (text) {
    const kws = await getJsonCfg("block_keywords", env);
    const hit = (Array.isArray(kws) ? kws : []).some(k => safeRegexTest(k, text));
    if (hit) {
      const c = u.block_count + 1;
      const max = parseInt(await getCfg("block_threshold", env), 10) || 5;
      await updUser(id, { block_count: c, is_blocked: c >= max }, env);
      if (c >= max) {
        await manageBlacklist(env, u, msg.from, true);
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 您已被系统自动封禁" });
      }
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `⚠️ 含有违禁词，请勿发送 (${c}/${max})` });
    }
  }

  for (const t of MSG_TYPES) {
    if (t.check(msg)) {
      const enabled = t.extra ? await getBool(t.extra(msg), env) : await getBool(t.key, env);
      if (!enabled && !(await isAuthAdmin(id, env))) {
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `⚠️ 系统不接收 ${t.name}` });
      }
      break;
    }
  }

  if (text) {
    const rules = await getJsonCfg("keyword_responses", env);
    const match = (Array.isArray(rules) ? rules : []).find(r => r && safeRegexTest(r.keywords, text));
    if (match) api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: match.response }).catch(() => {});
  }

  if (await getBool("busy_mode", env)) {
    const now = Date.now();
    if (now - (u.user_info.last_busy_reply || 0) > 300000) {
      api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "🌙 " + (await getCfg("busy_msg", env)) }).catch(() => {});
      await updUser(id, { user_info: { last_busy_reply: now } }, env);
    }
  }

  await relayToTopic(msg, u, env, ctx);
}

// --- 11. 转发到话题 (结合 aa 稳定性 + 3.71 撤回记录) ---
async function relayToTopic(msg, u, env, ctx) {
  const uid = u.user_id;

  // 保险：若中途被屏蔽（并发情况下），直接终止
  if (u.is_blocked && !(await isAuthAdmin(uid, env))) return;

  const uMeta = getUMeta(msg.from, u, msg.date);
  let tid = u.topic_id;

  if (!tid) {
    const now = Date.now();
    const staleBefore = now - TOPIC_LOCK_STALE_MS;

    const lockRes = await tryRun(
      env,
      `UPDATE users
       SET topic_creating=1, topic_create_ts=?
       WHERE user_id=?
         AND (topic_id IS NULL OR topic_id='')
         AND (topic_creating=0 OR topic_create_ts < ?)`,
      [now, uid, staleBefore]
    );

    const locked = (lockRes?.meta?.changes ?? lockRes?.changes ?? 0) === 1;

    if (locked) {
      try {
        const fresh = await getUser(uid, env);
        if (fresh.topic_id) {
          tid = fresh.topic_id;
        } else {
          const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: uMeta.topicName });
          tid = t.message_thread_id.toString();

          await updUser(uid, { topic_id: tid, topic_creating: 0, topic_create_ts: 0 }, env);
          u.topic_id = tid;

          // ✅ 关键：按 aa_2.txt 标准带上 msg.date，保证资料卡时间与主页按钮 100% 正常
          await sendInfoCardToTopic(env, u, msg.from, tid, msg.date);
        }
      } catch (e) {
        console.error("Topic Create Error:", e);
        await updUser(uid, { topic_creating: 0 }, env);
        const existUser = await getUser(uid, env);
        if (existUser.topic_id) tid = existUser.topic_id;
        else return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙，请稍后重试" });
      }
    } else {
      for (let i = 0; i < TOPIC_LOCK_POLL_MAX; i++) {
        const delay = Math.min(1500, TOPIC_LOCK_POLL_BASE_MS * Math.pow(2, i)) + Math.floor(Math.random() * 60);
        await sleep(delay);

        const fresh = await getUser(uid, env);
        if (fresh.topic_id) {
          tid = fresh.topic_id;
          u.topic_id = tid;
          break;
        }
      }

      if (!tid) {
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 系统繁忙，请稍后重试" });
      }
    }
  }

  if (!tid) return;

  let relaySuccess = false;
  try {
    await api(env.BOT_TOKEN, "forwardMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      from_chat_id: uid,
      message_id: msg.message_id,
      message_thread_id: tid
    });
    relaySuccess = true;
  } catch {
    try {
      const extra = {};
      if (msg.text) extra.text = msg.text;
      if (msg.caption) extra.caption = msg.caption;
      await api(env.BOT_TOKEN, "copyMessage", {
        chat_id: env.ADMIN_GROUP_ID,
        from_chat_id: uid,
        message_id: msg.message_id,
        message_thread_id: tid,
        ...extra
      });
      relaySuccess = true;
    } catch (cpErr) {
      console.error("Copy Failed:", cpErr);
      if (cpErr.message && (cpErr.message.includes("thread") || cpErr.message.includes("not found"))) {
        await updUser(uid, { topic_id: null }, env);
        return api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "⚠️ 会话已过期，请重发" });
      }
    }
  }

  if (relaySuccess) {
    const dk = `delivered:${uid}:${msg.message_id}`;
    if (!CACHE.locks.has(dk)) {
      CACHE.locks.add(dk);
      setTimeout(() => CACHE.locks.delete(dk), 20000);
      await markDelivered(env, uid, msg.message_id); // ✅ 补上 await，杜绝被 Worker 冻结
    }

    if (msg.text) {
      try {
        await sql(env, "INSERT OR REPLACE INTO messages (user_id, message_id, text, date) VALUES (?,?,?,?)", [
          uid,
          msg.message_id,
          msg.text,
          msg.date
        ]);
      } catch {}
      maybeCleanupMessages(env, ctx);
    }

    try {
  await handleInbox(env, msg, u, tid, uMeta);
} catch (inboxErr) {
  console.error("handleInbox Execution Error:", inboxErr);
}
try {
  await handleBackup(msg, uMeta, env);
} catch {}
  }
}
async function markDelivered(env, chatId, messageId) {
  try {
    await api(env.BOT_TOKEN, "setMessageReaction", {
      chat_id: chatId,
      message_id: parseInt(messageId),
      reaction: [{ type: "emoji", emoji: DELIVERED_REACTION }],
      is_big: false
    });
  } catch (e) {
    console.error("【贴送达表情失败】:", e?.message || e);
  }
}
// --- 12. 资料卡 (从 aa_2.txt 完美移植) ---
async function sendInfoCardToTopic(env, u, tgUser, tid, date) {
  const meta = getUMeta(tgUser, u, date || Date.now() / 1000);
  try {
    // 第一次尝试：原汁原味带上所有按钮发送
    const card = await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      message_thread_id: tid,
      text: meta.card,
      parse_mode: "HTML",
      reply_markup: getBtns(u.user_id, u.is_blocked)
    });
    await updUser(u.user_id, { user_info: { card_msg_id: card.message_id } }, env);
    api(env.BOT_TOKEN, "pinChatMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: card.message_id, message_thread_id: tid }).catch(() => {});
    return card.message_id;
  } catch (e) {
    // 🚨 触发降级：如果因为隐私设置报错，直接拔掉【主页】按钮重发！
    try {
      const fallbackBtns = getBtns(u.user_id, u.is_blocked);
      // 移除惹祸的第一排 [👤 主页] 按钮
      fallbackBtns.inline_keyboard.shift(); 
      
      const card = await api(env.BOT_TOKEN, "sendMessage", {
        chat_id: env.ADMIN_GROUP_ID,
        message_thread_id: tid,
        text: meta.card,
        parse_mode: "HTML",
        reply_markup: fallbackBtns
      });
      await updUser(u.user_id, { user_info: { card_msg_id: card.message_id } }, env);
      api(env.BOT_TOKEN, "pinChatMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: card.message_id, message_thread_id: tid }).catch(() => {});
      return card.message_id;
    } catch (fallbackErr) {
      return null;
    }
  }
}

// --- 13. 未读通知 (还原备份逻辑 + 彻底修复版) ---
async function handleInbox(env, msg, u, tid, uMeta) {
  // 防抖降噪：3秒内同一用户只处理一次
  const lk = `inbox:${u.user_id}`;
  if (CACHE.locks.has(lk)) return;
  CACHE.locks.add(lk);
  setTimeout(() => CACHE.locks.delete(lk), 3000);

  // 1. 读取话题 ID，不存在则直接建话题（与备份代码完全一致）
  let inboxId = await getCfg("unread_topic_id", env);
  if (!inboxId) {
    try {
      const t = await api(env.BOT_TOKEN, "createForumTopic", {
        chat_id: env.ADMIN_GROUP_ID,
        name: "🔔 未读消息"
      });
      inboxId = t.message_thread_id.toString();
      await setCfg("unread_topic_id", inboxId, env);
    } catch (createErr) {
      console.error("创建未读话题失败:", createErr);
      return;
    }
  }

  const gid = env.ADMIN_GROUP_ID.toString().replace(/^-100/, "");
  const preview = msg.text ? (msg.text.length > 20 ? msg.text.substring(0, 20) + "..." : msg.text) : "[媒体消息]";
  
  // 保底容错：确保 card 文本存在，绝不发空消息
  const cardInfo = (uMeta && uMeta.card) ? uMeta.card : `🆔: <code>${u.user_id}</code>`;
  const cardText = `<b>🔔 新消息</b>\n${cardInfo}\n📝 <b>预览:</b> ${escapeHTML(preview)}`;
  
  const kb = {
    inline_keyboard: [[
      { text: "🚀 直达回复", url: `https://t.me/c/${gid}/${tid}` },
      { text: "✅ 已阅", callback_data: `inbox:del:${u.user_id}` }
    ]]
  };

  try {
    // 2. 如果存在旧卡片，优先更新旧卡片
    if (u.user_info && u.user_info.inbox_msg_id) {
      try {
        await api(env.BOT_TOKEN, "editMessageText", {
          chat_id: env.ADMIN_GROUP_ID,
          message_id: u.user_info.inbox_msg_id,
          message_thread_id: inboxId,
          text: cardText,
          parse_mode: "HTML",
          reply_markup: kb
        });
        await updUser(u.user_id, { user_info: { last_notify: Date.now() } }, env);
        return;
      } catch (editErr) {
        // 如果旧卡片已被删除，重置消息 ID，继续向下发送新消息
        await updUser(u.user_id, { user_info: { inbox_msg_id: null } }, env);
        if (u.user_info) u.user_info.inbox_msg_id = null;
      }
    }

    // 3. 发送新未读提醒卡片
    const nm = await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      message_thread_id: inboxId,
      text: cardText,
      parse_mode: "HTML",
      reply_markup: kb
    });
    if (nm && nm.message_id) {
      await updUser(u.user_id, { user_info: { last_notify: Date.now(), inbox_msg_id: nm.message_id } }, env);
    }
  } catch (e) {
    console.error("未读通知发送失败:", e);
    // 4. 关键自愈：如果话题在群里被手动删除了（报错包含 thread），立刻清空 ID，下次来消息自动新建！
    if (e.message && e.message.includes("thread")) {
      await setCfg("unread_topic_id", "", env);
    }
  }
}
// --- 14. 黑名单/备份 ---
async function manageBlacklist(env, u, tgUser, isBlocking) {
  let bid = await getCfg("blocked_topic_id", env);
  if (!bid && isBlocking) {
    try {
      const t = await api(env.BOT_TOKEN, "createForumTopic", { chat_id: env.ADMIN_GROUP_ID, name: "🚫 黑名单" });
      bid = t.message_thread_id.toString();
      await setCfg("blocked_topic_id", bid, env);
    } catch { return; }
  }
  if (!bid) return;

  if (isBlocking) {
    const meta = getUMeta(tgUser, u, Date.now() / 1000);
    const m = await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID, message_thread_id: bid,
      text: `<b>🚫 用户已屏蔽</b>\n${meta.card}`, parse_mode: "HTML",
      reply_markup: { inline_keyboard: [[{ text: "✅ 解除屏蔽", callback_data: `unblock:${u.user_id}` }]] }
    }).catch(() => {});
    if (m) await updUser(u.user_id, { user_info: { blacklist_msg_id: m.message_id } }, env);
  } else {
    if (u.user_info.blacklist_msg_id) {
      api(env.BOT_TOKEN, "deleteMessage", { chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.blacklist_msg_id }).catch(() => {});
      await updUser(u.user_id, { user_info: { blacklist_msg_id: null } }, env);
    }
  }
}

async function handleBackup(msg, meta, env) {
  const bid = await getCfg("backup_group_id", env);
  if (!bid) return;
  try {
    await api(env.BOT_TOKEN, "copyMessage", { chat_id: bid, from_chat_id: msg.chat.id, message_id: msg.message_id });
  } catch {
    if (msg.text) api(env.BOT_TOKEN, "sendMessage", {
      chat_id: bid, text: `<b>备份</b> ${escapeHTML(meta.name)}:\n${escapeHTML(msg.text)}`, parse_mode: "HTML"
    }).catch(() => {});
  }
}

// --- 15. 图形验证码生成 ---
const _ri = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

function generateImageCaptcha() {
  const templates = [
    () => { const a = _ri(1, 9), b = _ri(1, 9); return { q: `${a} + ${b} = ?`, ans: (a + b).toString() }; },
    () => { const a = _ri(3, 9), b = _ri(1, a - 1); return { q: `${a} - ${b} = ?`, ans: (a - b).toString() }; },
    () => { const a = _ri(2, 5), b = _ri(2, 5); return { q: `${a} × ${b} = ?`, ans: (a * b).toString() }; }
  ];
  const { q, ans } = templates[_ri(0, 2)]();
  return { svg: buildCaptchaSvg(q), answer: ans };
}

function buildCaptchaSvg(text) {
  const W = 200, H = 64;
  const enc = s => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  // 干扰线
  let noise = "";
  for (let i = 0; i < 6; i++) {
    const c = `#${_ri(9, 13).toString(16)}${_ri(9, 13).toString(16)}${_ri(9, 13).toString(16)}`;
    noise += `<line x1="${_ri(0, W)}" y1="${_ri(0, H)}" x2="${_ri(0, W)}" y2="${_ri(0, H)}" stroke="${c}" stroke-width="1.2"/>`;
  }
  // 噪点
  for (let i = 0; i < 28; i++) {
    noise += `<circle cx="${_ri(0, W)}" cy="${_ri(0, H)}" r="1.3" fill="#c0c0c0"/>`;
  }
  // 字符（随机位置 + 旋转 + 颜色）
  const chars = [...text];
  const gap = Math.min(26, (W - 24) / chars.length);
  let texts = "";
  chars.forEach((c, i) => {
    const x = 12 + i * gap + _ri(-2, 2);
    const y = H / 2 + _ri(-5, 5);
    const rot = _ri(-14, 14);
    const sz = _ri(20, 26);
    const clr = ["#1a237e", "#1b5e20", "#b71c1c", "#4a148c", "#e65100"][i % 5];
    texts += `<text x="${x}" y="${y}" font-size="${sz}" fill="${clr}" transform="rotate(${rot},${x},${y})" font-family="Arial,sans-serif" font-weight="bold">${enc(c)}</text>`;
  });

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}"><rect width="${W}" height="${H}" fill="#f7f7f7" rx="6"/>${noise}${texts}</svg>`;
}

// --- 16. Web 验证页（Mini App） ---
async function handleVerifyPage(url, env) {
  const uid = url.searchParams.get("user_id");
  const nonce = url.searchParams.get("nonce") || "";
  const mode = await getCfg("captcha_mode", env);
  const siteKey = mode === "recaptcha" ? env.RECAPTCHA_SITE_KEY : env.TURNSTILE_SITE_KEY;
  const imgCaptchaOn = await getBool("enable_image_captcha", env);

  if (!uid) return new Response("Misconfigured", { status: 400 });
  if (!imgCaptchaOn && !siteKey) return new Response("Misconfigured", { status: 400 });

  // 生成图形验证码（需先校验 nonce 合法性，防止任意人刷写 DB）
  let captchaBlock = "";
  if (imgCaptchaOn) {
    const u = await getUser(uid, env);
    const savedNonce = (u.user_info?.verify_nonce || "").toString();
    const savedTs = Number(u.user_info?.verify_nonce_ts || 0);
    const expired = !savedTs || Date.now() - savedTs > VERIFY_NONCE_TTL_MS;
    if (!savedNonce || expired || nonce !== savedNonce) {
      return new Response("链接已失效，请重新发送 /start", {
        status: 400, headers: { "Content-Type": "text/plain;charset=utf-8" }
      });
    }
    const cap = generateImageCaptcha();
    await updUser(uid, { user_info: { img_captcha_ans: cap.answer, img_captcha_ts: Date.now() } }, env);

    // SVG → base64 作为 <img> src，避免直接拼 HTML
    const svgBytes = new TextEncoder().encode(cap.svg);
    let binary = "";
    for (const b of svgBytes) binary += String.fromCharCode(b);
    const captchaSvgB64 = btoa(binary);

    captchaBlock = `
      <div style="margin:12px 0">
        <img src="data:image/svg+xml;base64,${captchaSvgB64}" alt="验证码"
             style="border:1px solid #ddd;border-radius:6px;display:block;margin:0 auto;max-width:100%"/>
        <div style="text-align:center;margin-top:4px">
          <a href="/verify?user_id=${encodeURIComponent(uid)}&nonce=${encodeURIComponent(nonce)}"
             style="font-size:12px;color:#666;text-decoration:none">🔄 看不清？换一张</a>
        </div>
        <input id="imgAns" type="text" inputmode="numeric" maxlength="4"
               placeholder="请输入图中算式答案"
               style="width:100%;box-sizing:border-box;margin-top:8px;padding:8px 10px;
                      border:1px solid #ccc;border-radius:6px;font-size:16px;text-align:center"/>
      </div>`;
  }

  // 外部验证码 widget（Turnstile 或 reCAPTCHA）
  const needExternalCaptcha = !!siteKey;
  const script = mode === "recaptcha"
    ? "https://www.google.com/recaptcha/api.js"
    : "https://challenges.cloudflare.com/turnstile/v0/api.js";
  const divClass = mode === "recaptcha" ? "g-recaptcha" : "cf-turnstile";

  // 当图形验证码与外部验证码同时开启时：
  // Turnstile/reCAPTCHA 暂存 token，不直接提交；用户需手动点击"提交验证"
  let externalWidget;
  if (needExternalCaptcha && imgCaptchaOn) {
    // 两者同时开启：外部验证码完成后激活提交按钮
    externalWidget = `<script src="${script}" async defer><\/script>
       <div class="${divClass}" data-sitekey="${siteKey}" data-callback="onExternalDone"
            style="margin-top:8px;display:flex;justify-content:center"></div>
       <button id="submitBtn" onclick="S()" disabled
            style="width:100%;padding:10px;background:#2563eb;color:#fff;
                   border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:12px;opacity:0.5">
            ✅ 提交验证（请先完成上方验证）</button>`;
  } else if (needExternalCaptcha) {
    // 仅外部验证码：完成即自动提交
    externalWidget = `<script src="${script}" async defer><\/script>
       <div class="${divClass}" data-sitekey="${siteKey}" data-callback="S"
            style="margin-top:8px;display:flex;justify-content:center"></div>`;
  } else {
    // 无外部验证码：直接显示提交按钮
    externalWidget = `<button onclick="S()"
         style="width:100%;padding:10px;background:#2563eb;color:#fff;
                border:none;border-radius:8px;font-size:16px;cursor:pointer;margin-top:12px">
         ✅ 提交验证</button>`;
  }

  const html = `<!DOCTYPE html><html><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://telegram.org/js/telegram-web-app.js"><\/script>
<style>
*{box-sizing:border-box}
body{display:flex;justify-content:center;align-items:center;min-height:100vh;
     background:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:0;padding:16px}
#c{text-align:center;padding:20px;background:#f5f5f5;border-radius:12px;
   width:100%;max-width:340px;box-shadow:0 1px 6px rgba(0,0,0,.08)}
h3{margin:0 0 16px;font-size:16px;color:#333}
#m{margin-top:10px;font-size:14px;min-height:20px}
</style>
</head><body>
<div id="c">
  <h3>🛡️ 安全验证</h3>
  ${captchaBlock}
  ${externalWidget}
  <div id="m"></div>
</div>
<script>
const tg = window.Telegram.WebApp; tg.ready();
const UI_USER_ID  = '${escapeHTML(uid)}';
const UI_NONCE    = '${escapeHTML(nonce)}';
const IMG_ON      = ${imgCaptchaOn ? "true" : "false"};
const EXTERNAL_ON = ${needExternalCaptcha ? "true" : "false"};
let _externalToken = '';

// 外部验证码完成回调（仅在两者同时开启时使用）
function onExternalDone(token) {
  _externalToken = token;
  const btn = document.getElementById('submitBtn');
  if (btn) {
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.textContent = '✅ 提交验证';
  }
}

// 主提交函数
// - 仅外部验证码模式：data-callback="S" 自动传入 token
// - 仅图形验证码 / 手动按钮模式：onclick="S()" token 为 undefined，用 _externalToken
function S(token) {
  const finalToken = (token !== undefined && token !== null) ? token : _externalToken;

  if (IMG_ON) {
    const el  = document.getElementById('imgAns');
    const ans = el ? el.value.trim() : '';
    if (!ans) { document.getElementById('m').innerText = '⚠️ 请输入图形验证码答案'; return; }
  }

  if (EXTERNAL_ON && IMG_ON && !finalToken) {
    document.getElementById('m').innerText = '⚠️ 请先完成上方的人机验证';
    return;
  }

  document.getElementById('m').innerText = '验证中...';
  const initData  = tg.initData || '';
  const imgAnswer = IMG_ON ? ((document.getElementById('imgAns') || {}).value || '').trim() : '';

  fetch('/submit_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: finalToken, userId: UI_USER_ID, nonce: UI_NONCE, initData, imgAnswer })
  })
  .then(r => r.json())
  .then(d => {
    if (d.success) {
      document.getElementById('m').innerText = '✅ 验证通过！';
      setTimeout(() => { tg.close(); try { window.close(); } catch(e) {} }, 800);
    } else {
      document.getElementById('m').innerText = '❌ ' + (d.reason || '验证失败，请重试');
      // 图形验证码错误时清空输入框
      const el = document.getElementById('imgAns');
      if (el) el.value = '';
    }
  })
  .catch(() => { document.getElementById('m').innerText = '⚠️ 网络错误，请重试'; });
}
<\/script>
</body></html>`;

  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// --- 17. Token 提交处理 ---
async function handleTokenSubmit(req, env, ctx) {
  try {
    const body = await req.json();
    const token     = body?.token;
    const uiUserId  = (body?.userId  || "").toString();
    const nonce     = (body?.nonce   || "").toString();
    const initData  = (body?.initData || "").toString();
    const imgAnswer = (body?.imgAnswer || "").toString().trim();
    const mode      = await getCfg("captcha_mode", env);

    // IP 级限流
    const rlPre = await checkSubmitRateLimit(req, env, ctx, "");
    if (!rlPre.allowed) throw new Error("Rate limited");

    // initData 验签
    if (!initData || initData.length < 20) throw new Error("Missing initData");
    const parsed = await verifyTelegramInitData(initData, env.BOT_TOKEN, 600);
    const uid = parsed?.userId?.toString();
    if (!uid) throw new Error("Missing uid");

    // uid 级限流
    const rlUid = await checkSubmitRateLimit(req, env, ctx, uid);
    if (!rlUid.allowed) throw new Error("Rate limited");

    if (uiUserId && uiUserId !== uid) throw new Error("uid mismatch");

    const u = await getUser(uid, env);

    // 屏蔽用户不允许验证推进
    if (u.is_blocked && !(await isAuthAdmin(uid, env))) throw new Error("blocked");

    // ✅ 图形验证码校验
    const imgCaptchaOn = await getBool("enable_image_captcha", env);
    if (imgCaptchaOn) {
      const storedAns = (u.user_info?.img_captcha_ans || "").toString().trim();
      const storedTs  = Number(u.user_info?.img_captcha_ts || 0);

      if (!storedAns || Date.now() - storedTs > IMG_CAPTCHA_TTL_MS) {
        return new Response(
          JSON.stringify({ success: false, reason: "图形验证码已过期，请关闭后重新点击验证按钮" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }
      if (!imgAnswer || imgAnswer !== storedAns) {
        return new Response(
          JSON.stringify({ success: false, reason: "图形验证码错误，请重新输入" }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }
      // 用完即清，防重放
      await updUser(uid, { user_info: { img_captcha_ans: "", img_captcha_ts: 0 } }, env);
    }

    // nonce 校验
    const savedNonce = (u.user_info?.verify_nonce || "").toString();
    const savedTs    = Number(u.user_info?.verify_nonce_ts || 0);
    const now        = Date.now();
    const expired    = !savedTs || now - savedTs > VERIFY_NONCE_TTL_MS;

    if (u.user_state === "verified") {
      return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
    }

    const vOn = await getBool("enable_verify", env);
    if (vOn) {
      if (!nonce || !savedNonce || expired || nonce !== savedNonce) throw new Error("nonce invalid");
      await updUser(uid, { user_info: { verify_nonce: "", verify_nonce_ts: 0 } }, env);
    }

    // 外部 CAPTCHA 验证（Turnstile / reCAPTCHA）
    if (vOn) {
      const verifyUrl = mode === "recaptcha"
        ? "https://www.google.com/recaptcha/api/siteverify"
        : "https://challenges.cloudflare.com/turnstile/v0/siteverify";
      const params = mode === "recaptcha"
        ? new URLSearchParams({ secret: env.RECAPTCHA_SECRET_KEY, response: token })
        : JSON.stringify({ secret: env.TURNSTILE_SECRET_KEY, response: token });
      const headers = mode === "recaptcha"
        ? { "Content-Type": "application/x-www-form-urlencoded" }
        : { "Content-Type": "application/json" };
      const r = await fetch(verifyUrl, { method: "POST", headers, body: params });
      const d = await r.json();
      if (!d.success) throw new Error("Token Invalid");
    }

    // 更新用户信息
    try {
      if (parsed?.userObj) {
        const nm = ((parsed.userObj.first_name || "") + " " + (parsed.userObj.last_name || "")).trim() || (parsed.userObj.first_name || "");
        const patch = {};
        if (nm) patch.name = nm;
        if (parsed.userObj.username) patch.username = parsed.userObj.username.toString();
        if (parsed.authDate) patch.join_date = parsed.authDate;
        if (Object.keys(patch).length) await updUser(uid, { user_info: patch }, env);
      }
    } catch {}

    const qaOn = await getBool("enable_qa_verify", env);
    if (qaOn) {
      await updUser(uid, { user_state: "pending_verification" }, env);
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 验证通过！\n请继续回答：\n" + (await getCfg("verif_q", env)) });
    } else {
      await updUser(uid, { user_state: "verified" }, env);
      await api(env.BOT_TOKEN, "sendMessage", { chat_id: uid, text: "✅ 验证通过！\n请直接发送消息以联系管理员。" });
    }

    return new Response(JSON.stringify({ success: true }), { headers: { "Content-Type": "application/json" } });
  } catch {
    return new Response(JSON.stringify({ success: false }), { status: 400, headers: { "Content-Type": "application/json" } });
  }
}

// QA 验证
async function verifyAnswer(id, ans, env) {
  if (ans.trim() === (await getCfg("verif_a", env)).trim()) {
    await updUser(id, { user_state: "verified" }, env);
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "✅ 验证通过！\n请直接发送消息以联系管理员。" });
  } else {
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 错误" });
  }
}

// --- 18. initData 验签 ---
async function verifyTelegramInitData(initData, botToken, maxAgeSec) {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash") || "";
  if (!hash) throw new Error("missing hash");
  const authDateStr = params.get("auth_date") || "";
  const authDate = parseInt(authDateStr, 10);
  if (!authDate || !Number.isFinite(authDate)) throw new Error("missing auth_date");
  const nowSec = Math.floor(Date.now() / 1000);
  if (maxAgeSec && nowSec - authDate > maxAgeSec) throw new Error("expired");
  const pairs = [];
  for (const [k, v] of params.entries()) { if (k === "hash") continue; pairs.push([k, v]); }
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join("\n");
  const secretKey = await hmacSha256Bytes(strToBytes("WebAppData"), strToBytes(botToken));
  const calc = await hmacSha256Bytes(secretKey, strToBytes(dataCheckString));
  const calcHex = bytesToHex(calc);
  if (!timingSafeEqualHex(calcHex, hash)) throw new Error("hash mismatch");
  const userJson = params.get("user");
  let userId = "", userObj = null;
  try {
    if (userJson) {
      userObj = JSON.parse(userJson);
      if (userObj && (userObj.id || userObj.id === 0)) userId = userObj.id.toString();
    }
  } catch {}
  return { userId, authDate, userObj };
}

function strToBytes(s) { return new TextEncoder().encode(s); }
async function hmacSha256Bytes(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return new Uint8Array(sig);
}
function bytesToHex(u8) { let out = ""; for (const b of u8) out += b.toString(16).padStart(2, "0"); return out; }
function timingSafeEqualHex(a, b) {
  const aa = (a || "").toLowerCase(), bb = (b || "").toLowerCase();
  if (aa.length !== bb.length) return false;
  let r = 0;
  for (let i = 0; i < aa.length; i++) r |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return r === 0;
}
function timingSafeEqualStr(a, b) {
  const aa = (a || "").toString(), bb = (b || "").toString();
  if (aa.length !== bb.length) return false;
  let r = 0;
  for (let i = 0; i < aa.length; i++) r |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  return r === 0;
}

// --- 19. 辅助函数 ---
const getBool = async (k, e) => (await getCfg(k, e)) === "true";
const getJsonCfg = async (k, e) => safeParse(await getCfg(k, e), []);

function escapeHTML(t) {
  return (t || "").toString()
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function safeRegexTest(pattern, text) {
  try {
    if (!pattern || typeof pattern !== "string") return false;
    const p = pattern.trim();
    if (!p || p.length > REGEX_MAX_PATTERN_LEN) return false;
    for (const re of REGEX_REJECT_PATTERNS) { if (re.test(p)) return false; }
    const t = (text || "").toString();
    const t2 = t.length > REGEX_MAX_TEXT_LEN ? t.slice(0, REGEX_MAX_TEXT_LEN) : t;
    return new RegExp(p, "gi").test(t2);
  } catch { return false; }
}

function genNonce(len = 24) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let s = "";
  for (const b of bytes) s += (b % 36).toString(36);
  return s;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const getUMeta = (tgUser, dbUser, d) => {
  const id = tgUser.id.toString();
  const name = (((tgUser.first_name || "") + " " + (tgUser.last_name || "")).trim() || tgUser.first_name || "User");
  const timeStr = new Date(d * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
  const note = dbUser.user_info?.note ? `\n📝 <b>备注:</b> ${escapeHTML(dbUser.user_info.note)}` : "";
  return {
    userId: id,
    name,
    topicName: `${name} | ${id}`.substring(0, 128),
    card: `<b>🪪 用户资料</b>\n👤: <code>${escapeHTML(name)}</code>\n🆔: <code>${escapeHTML(id)}</code>${note}\n🕒: <code>${escapeHTML(timeStr)}</code>`
  };
};

const getBtns = (id, blk) => ({
  inline_keyboard: [
    [{ text: "👤 主页", url: `tg://user?id=${id}` }],
    [{ text: blk ? "✅ 解封" : "🚫 屏蔽", callback_data: `${blk ? "unblock" : "block"}:${id}` }],
    [{ text: "✏️ 备注", callback_data: `note:set:${id}` }, { text: "📌 置顶", callback_data: `pin_card:${id}` }]
  ]
});

// --- 20. Commands ---
async function registerCommands(env) {
  try {
    await api(env.BOT_TOKEN, "deleteMyCommands", { scope: { type: "default" } });
    await api(env.BOT_TOKEN, "setMyCommands", { commands: [{ command: "start", description: "开始 / Start" }], scope: { type: "default" } });
    const admins = [...(env.ADMIN_IDS || "").split(/[,，]/), ...(await getJsonCfg("authorized_admins", env))];
    const uniqueAdmins = [...new Set(admins.map(i => i.toString().trim()).filter(Boolean))];
    for (const id of uniqueAdmins) {
      await api(env.BOT_TOKEN, "setMyCommands", {
        commands: [
          { command: "start", description: "面板" },
          { command: "help", description: "帮助" },
          { command: "reset", description: "重置用户验证(主管理员)" },
          { command: "recall", description: "撤回发给用户的所有消息" }
        ],
        scope: { type: "chat", chat_id: id }
      });
    }
  } catch {}
}

// --- 21. 回调处理 ---
async function handleCallback(cb, env) {
  const { data, message: msg, from } = cb;
  const [act, p1, p2] = (data || "").split(":");

  if (act === "inbox" && p1 === "del") {
    await api(env.BOT_TOKEN, "deleteMessage", { chat_id: msg.chat.id, message_id: msg.message_id }).catch(() => {});
    if (p2) {
      const u = await getUser(p2, env);
      await updUser(p2, { user_info: { ...u.user_info, last_notify: 0 } }, env);
    }
    return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "已处理" }).catch(() => {});
  }

  if (act === "note" && p1 === "set") {
    await setCfg(`admin_state:${from.id}`, JSON.stringify({ action: "input_note", target: p2 }), env);
    return api(env.BOT_TOKEN, "sendMessage", {
      chat_id: msg.chat.id, message_thread_id: msg.message_thread_id,
      text: "⌨️ 请回复备注内容 (回复 /clear 清除):"
    });
  }

  if (act === "config") {
    if (!(await isPrimaryAdmin(from.id, env))) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    await api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id }).catch(() => {});
    const [, t, k, v] = (data || "").split(":");
    return handleAdminConfig(msg.chat.id, msg.message_id, t, k, v, env);
  }

  if (msg.chat.id.toString() === env.ADMIN_GROUP_ID && ["block", "unblock"].includes(act)) {
    if (!(await isAuthAdmin(from.id, env))) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    const isB = act === "block";
    const uid = p1;
    const u = await getUser(uid, env);
    await updUser(uid, { is_blocked: isB, block_count: 0 }, env);
    if (u.user_info.card_msg_id) {
      api(env.BOT_TOKEN, "editMessageReplyMarkup", {
        chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.card_msg_id,
        reply_markup: getBtns(uid, isB)
      }).catch(() => {});
    }
    await manageBlacklist(env, u, { id: uid, first_name: u.user_info.name || "User", username: u.user_info.username }, isB);
    api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: isB ? "已屏蔽" : "已解封" }).catch(() => {});
  }

  if (act === "pin_card") {
    if (!(await isAuthAdmin(from.id, env))) {
      return api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "无权", show_alert: true }).catch(() => {});
    }
    api(env.BOT_TOKEN, "pinChatMessage", { chat_id: msg.chat.id, message_id: msg.message_id, message_thread_id: msg.message_thread_id }).catch(() => {});
    api(env.BOT_TOKEN, "answerCallbackQuery", { callback_query_id: cb.id, text: "已置顶" }).catch(() => {});
  }
}

// --- 22. 管理员回复 ---
async function handleAdminReply(msg, env) {
  if (!msg.message_thread_id || msg.from.is_bot || !(await isAuthAdmin(msg.from.id, env))) return;

  const stateStr = await getCfg(`admin_state:${msg.from.id}`, env);
  if (stateStr) {
    const state = safeParse(stateStr);
    if (state.action === "input_note") {
      const u = await getUser(state.target, env);
      u.user_info.note = msg.text === "/clear" || msg.text === "清除" ? "" : msg.text;
      await updUser(state.target, { user_info: u.user_info }, env);
      await setCfg(`admin_state:${msg.from.id}`, "", env);
      if (u.topic_id && u.user_info.card_msg_id) {
        const meta = getUMeta(
          { id: state.target, first_name: u.user_info.name, username: u.user_info.username },
          u, u.user_info.join_date || Date.now() / 1000
        );
        api(env.BOT_TOKEN, "editMessageText", {
          chat_id: env.ADMIN_GROUP_ID, message_id: u.user_info.card_msg_id,
          text: meta.card, parse_mode: "HTML", reply_markup: getBtns(state.target, u.is_blocked)
        }).catch(() => {});
      }
      return api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "✅ 备注已更新" });
    }
  }

  const uid = (await sql(env, "SELECT user_id FROM users WHERE topic_id = ?", msg.message_thread_id.toString(), "first"))?.user_id;
  if (!uid) return;
  try {
    const sent = await api(env.BOT_TOKEN, "copyMessage", { chat_id: uid, from_chat_id: msg.chat.id, message_id: msg.message_id });
    // 记录 bot 发给用户的消息，供话题关闭时批量撤回
    if (sent?.message_id) {
      await sql(env, "INSERT INTO admin_msgs (user_id, message_id) VALUES (?, ?)",
        [uid, sent.message_id.toString()]);
    }
  } catch {
    api(env.BOT_TOKEN, "sendMessage", { chat_id: msg.chat.id, message_thread_id: msg.message_thread_id, text: "❌ 发送失败 (用户可能已停止Bot)" }).catch(() => {});
  }
}

// --- 23. 编辑消息提示 (加固版) ---
async function handleEdit(msg, env) {
  const uid = msg.from.id.toString();
  const u = await getUser(uid, env);
  let tid = u?.topic_id;

  // 容错：如果用户表的 topic_id 偶发丢失，尝试从历史消息里回溯定位话题
  if (!tid) {
    const row = await sql(env, "SELECT topic_id FROM users WHERE user_id = ?", uid, "first");
    tid = row?.topic_id;
  }

  if (tid) {
    const txt = msg.text || msg.caption || "[非文本]";
    await api(env.BOT_TOKEN, "sendMessage", {
      chat_id: env.ADMIN_GROUP_ID,
      message_thread_id: tid,
      text: `✏️ <b>用户修改了消息:</b>\n${escapeHTML(txt)}`,
      parse_mode: "HTML"
    }).catch(e => console.error("Send Edit Notice Failed:", e));
  }
}

// --- 24. 管理员面板 ---
async function handleAdminConfig(cid, mid, type, key, val, env) {
  const render = (txt, kb) => api(env.BOT_TOKEN, mid ? "editMessageText" : "sendMessage", {
    chat_id: cid, message_id: mid, text: txt, parse_mode: "HTML", reply_markup: kb
  });
  const back = { text: "🔙 返回主菜单", callback_data: "config:menu" };

  try {
    // ── 主菜单 ──────────────────────────────────────────────
    if (!type || type === "menu") {
      if (!key) {
        const busyOn = await getBool("busy_mode", env);
        return render(
          `⚙️ <b>控制面板</b>
营业状态: ${busyOn ? "🔴 休息中" : "🟢 营业中"}`,
          {
            inline_keyboard: [
              [{ text: "📝 欢迎语",   callback_data: "config:edit:welcome_msg" },
               { text: "🔐 验证方式", callback_data: "config:menu:verify" }],
              [{ text: "🤖 自动回复", callback_data: "config:menu:ar" },
               { text: "🚫 屏蔽词",   callback_data: "config:menu:kw" }],
              [{ text: "🛠 消息过滤", callback_data: "config:menu:fl" },
               { text: "👮 协管员",   callback_data: "config:menu:auth" }],
              [{ text: "💾 备份/通知", callback_data: "config:menu:bak" },
               { text: `${busyOn ? "🟢 切换营业" : "🔴 切换休息"}`, callback_data: `config:toggle:busy_mode:${!busyOn}` }]
            ]
          }
        );
      }

      // ── 验证方式 ──────────────────────────────────────────
      if (key === "verify") {
        const mode      = await getCfg("captcha_mode", env);
        const captchaOn = await getBool("enable_verify", env);
        const qaOn      = await getBool("enable_qa_verify", env);
        const imgOn     = await getBool("enable_image_captcha", env);
        let captchaLabel = "❌ 关闭";
        if (captchaOn) captchaLabel = mode === "recaptcha" ? "✅ Google reCAPTCHA" : "✅ Cloudflare Turnstile";

        return render(
          `🔐 <b>验证方式</b>

外部验证码: ${captchaLabel}
图形验证码: ${imgOn ? "✅ 开启" : "❌ 关闭"}
问题验证: ${qaOn ? "✅ 开启" : "❌ 关闭"}

💡 可叠加使用，用户依次通过所有开启项`,
          {
            inline_keyboard: [
              [{ text: `外部验证码: ${captchaLabel} (点击轮换)`, callback_data: "config:rotate_mode" }],
              [{ text: `图形验证码: ${imgOn ? "✅ 开启" : "❌ 关闭"}`, callback_data: `config:toggle:enable_image_captcha:${!imgOn}` }],
              [{ text: `问题验证: ${qaOn ? "✅ 开启" : "❌ 关闭"}`, callback_data: `config:toggle:enable_qa_verify:${!qaOn}` }],
              [{ text: "✏️ 编辑验证问题", callback_data: "config:edit:verif_q" },
               { text: "✏️ 编辑答案", callback_data: "config:edit:verif_a" }],
              [back]
            ]
          }
        );
      }

      // ── 消息过滤 ──────────────────────────────────────────
      if (key === "fl") return render(`🛠 <b>消息过滤</b>
点击按钮切换开关`, await getFilterKB(env));

      // ── 列表类页面 ────────────────────────────────────────
      if (key === "ar")   return render("🤖 <b>自动回复规则</b>", await getListKB("ar", env));
      if (key === "kw")   return render("🚫 <b>屏蔽关键词</b>",   await getListKB("kw", env));
      if (key === "auth") return render("👮 <b>协管员列表</b>",   await getListKB("auth", env));

      // ── 备份/通知 ─────────────────────────────────────────
      if (key === "bak") {
        const bid = await getCfg("backup_group_id", env);
        const uid = await getCfg("unread_topic_id", env);
        const blk = await getCfg("blocked_topic_id", env);
        return render(
          `💾 <b>备份与通知</b>

备份群组: ${bid ? `<code>${bid}</code>` : "未设置"}
未读聚合话题: ${uid ? `✅ ID ${uid}` : "⏳ 自动创建"}
黑名单话题: ${blk ? `✅ ID ${blk}` : "⏳ 自动创建"}`,
          {
            inline_keyboard: [
              [{ text: "✏️ 设置备份群", callback_data: "config:edit:backup_group_id" },
               { text: "🗑 清除备份群", callback_data: "config:cl:backup_group_id" }],
              [{ text: "🔄 重置未读话题", callback_data: "config:cl:unread_topic_id" },
               { text: "🔄 重置黑名单话题", callback_data: "config:cl:blocked_topic_id" }],
              [back]
            ]
          }
        );
      }

      // ── 营业状态（独立页，保留给 toggle 后跳转用） ────────
      if (key === "busy") {
        const on      = await getBool("busy_mode", env);
        const msgText = await getCfg("busy_msg", env);
        return render(
          `🌙 <b>营业状态</b>

当前: ${on ? "🔴 休息中" : "🟢 营业中"}

休息回复语:
${escapeHTML(msgText)}`,
          {
            inline_keyboard: [
              [{ text: `切换为${on ? "🟢 营业" : "🔴 休息"}`, callback_data: `config:toggle:busy_mode:${!on}` }],
              [{ text: "✏️ 修改休息回复语", callback_data: "config:edit:busy_msg" }],
              [back]
            ]
          }
        );
      }
    }

    // ── toggle 开关 ────────────────────────────────────────
    if (type === "toggle") {
      await setCfg(key, val, env);
      if (key === "busy_mode") return handleAdminConfig(cid, mid, "menu", null, null, env);
      if (["enable_qa_verify", "enable_image_captcha", "enable_verify"].includes(key))
        return handleAdminConfig(cid, mid, "menu", "verify", null, env);
      return render(`🛠 <b>消息过滤</b>
点击按钮切换开关`, await getFilterKB(env));
    }

    // ── 清除配置 ──────────────────────────────────────────
    if (type === "cl") {
      await setCfg(key, key === "authorized_admins" ? "[]" : "", env);
      const backKey =
        ["unread_topic_id", "blocked_topic_id", "backup_group_id"].includes(key) ? "bak"
        : key === "authorized_admins" ? "auth" : null;
      return handleAdminConfig(cid, mid, "menu", backKey, null, env);
    }

    // ── 删除列表项 ────────────────────────────────────────
    if (type === "del") {
      const realK = key === "kw" ? "block_keywords" : key === "auth" ? "authorized_admins" : "keyword_responses";
      let l = await getJsonCfg(realK, env);
      l = (Array.isArray(l) ? l : []).filter(i => (i.id || i).toString() !== val);
      await setCfg(realK, JSON.stringify(l), env);
      return handleAdminConfig(cid, mid, "menu", key, null, env);
    }

    // ── 编辑/添加输入 ─────────────────────────────────────
    if (type === "edit" || type === "add") {
      await setCfg(`admin_state:${cid}`, JSON.stringify({ action: "input", key: key + (type === "add" ? "_add" : "") }), env);
      const prompts = {
        welcome_msg: `📝 <b>编辑欢迎语</b>

发送新的欢迎语内容 (/cancel 取消)

• 支持文字或图片/视频/GIF
• 支持占位符 {name} 显示用户名
• 发送媒体时可附带文字说明`,
        verif_q:     `<b>编辑验证问题</b>

发送新的问题内容 (/cancel 取消)`,
        verif_a:     `✅ <b>编辑验证答案</b>

发送正确答案 (/cancel 取消)`,
        busy_msg:    `🌙 <b>编辑休息回复语</b>

发送新的回复内容 (/cancel 取消)`,
        backup_group_id: `💾 <b>设置备份群组</b>

发送群组 ID（如 -100123456789）
(/cancel 取消)`
      };
      const arAdd = key === "ar" && type === "add"
        ? `🤖 <b>添加自动回复规则</b>

格式：<b>关键词===回复内容</b>
例：价格===请联系人工客服

(/cancel 取消)`
        : null;
      const promptText = arAdd || prompts[key] || `请输入 ${key} 的值 (/cancel 取消)`;
      return api(env.BOT_TOKEN, "editMessageText", { chat_id: cid, message_id: mid, text: promptText, parse_mode: "HTML" });
    }

    // ── 外部验证码轮换 ────────────────────────────────────
    if (type === "rotate_mode") {
      const currentMode = await getCfg("captcha_mode", env);
      const isEnabled   = await getBool("enable_verify", env);
      let nextMode = "turnstile", nextEnable = "true", toast = "已切换为 Cloudflare Turnstile";
      if (isEnabled) {
        if (currentMode === "turnstile") { nextMode = "recaptcha"; toast = "已切换为 Google reCAPTCHA"; }
        else { nextEnable = "false"; nextMode = currentMode; toast = "外部验证码已关闭"; }
      }
      await setCfg("captcha_mode", nextMode, env);
      await setCfg("enable_verify", nextEnable, env);
      return handleAdminConfig(cid, mid, "menu", "verify", null, env);
    }

  } catch (e) {
    console.error("handleAdminConfig error:", e);
  }
}

async function getFilterKB(env) {
  const s = async k => ((await getBool(k, env)) ? "✅" : "❌");
  const b = (t, k, v) => ({ text: `${t} ${v}`, callback_data: `config:toggle:${k}:${v === "❌"}` });
  const keys = [
    "enable_forward_forwarding", "enable_image_forwarding", "enable_audio_forwarding",
    "enable_sticker_forwarding", "enable_link_forwarding", "enable_channel_forwarding", "enable_text_forwarding"
  ];
  const vals = await Promise.all(keys.map(k => s(k)));
  return {
    inline_keyboard: [
      [b("转发", keys[0], vals[0])],
      [b("媒体", keys[1], vals[1]), b("语音", keys[2], vals[2])],
      [b("贴纸", keys[3], vals[3]), b("链接", keys[4], vals[4])],
      [b("频道", keys[5], vals[5]), b("文本", keys[6], vals[6])],
      [{ text: "🔙 返回", callback_data: "config:menu" }]
    ]
  };
}

async function getListKB(type, env) {
  const k = type === "ar" ? "keyword_responses" : type === "kw" ? "block_keywords" : "authorized_admins";
  const l = await getJsonCfg(k, env);
  const btns = (Array.isArray(l) ? l : []).map(i => [{ text: `🗑 ${type === "ar" ? i.keywords : i}`, callback_data: `config:del:${type}:${i.id || i}` }]);
  btns.push([{ text: "➕ 添加", callback_data: `config:add:${type}` }], [{ text: "🔙 返回", callback_data: "config:menu" }]);
  return { inline_keyboard: btns };
}

async function handleAdminInput(id, msg, state, env) {
  const txt = msg.text || "";
  if (txt === "/cancel") {
    await sql(env, "DELETE FROM config WHERE key=?", `admin_state:${id}`);
    return handleAdminConfig(id, null, "menu", null, null, env);
  }

  let k = state.key, val = txt;
  try {
    if (k === "welcome_msg") {
      if (msg.photo || msg.video || msg.animation) {
        let fileId, type;
        if (msg.photo) { type = "photo"; fileId = msg.photo[msg.photo.length - 1].file_id; }
        else if (msg.video) { type = "video"; fileId = msg.video.file_id; }
        else if (msg.animation) { type = "animation"; fileId = msg.animation.file_id; }
        val = JSON.stringify({ type, file_id: fileId, caption: msg.caption || "" });
      } else {
        val = txt;
      }
    } else if (k.endsWith("_add")) {
      k = k.replace("_add", "");
      const realK = k === "ar" ? "keyword_responses" : k === "kw" ? "block_keywords" : "authorized_admins";
      const list = await getJsonCfg(realK, env);
      const arr = Array.isArray(list) ? list : [];
      if (k === "ar") {
        const [kk, rr] = txt.split("===");
        if (kk && rr) arr.push({ keywords: kk, response: rr, id: Date.now() });
        else return api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: "❌ 格式错误，请使用：关键词===回复内容" });
      } else arr.push(txt);
      val = JSON.stringify(arr);
      k = realK;
    } else if (k === "authorized_admins") {
      val = JSON.stringify(txt.split(/[,，]/).map(s => s.trim()).filter(Boolean));
    }

    await setCfg(k, val, env);
    await sql(env, "DELETE FROM config WHERE key=?", `admin_state:${id}`);
    const displayVal = val.startsWith("{") && k === "welcome_msg" ? "[媒体配置]" : val.substring(0, 100);
    await api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `✅ ${k} 已更新:\n${displayVal}` }).catch(() => {});
    await handleAdminConfig(id, null, "menu", null, null, env);
  } catch (e) {
    api(env.BOT_TOKEN, "sendMessage", { chat_id: id, text: `❌ 失败: ${e.message}` }).catch(() => {});
  }
}
