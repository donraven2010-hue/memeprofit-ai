// MemeProfit AI backend (Cloudflare Worker + D1 database)
// Stage 2: accounts, $100 paper-trading engine with server-enforced risk rules,
// automatic stop-loss / take-profit monitoring, notifications and system status.
// No real money, no wallets, no private keys.

const GT = 'https://api.geckoterminal.com/api/v2';
const CHAINS = ['solana', 'eth', 'bsc', 'base'];

const LIMITS = {
  START_BALANCE: 100,
  MAX_LOSS_PER_TRADE: 1,     // USD, includes estimated fees and slippage
  MAX_DAILY_LOSS: 3,         // USD realized, per UTC day
  MAX_OPEN: 3,
  FEE_RATE: 0.003,           // assumed 0.3% swap fee per side (estimate)
  BASE_SLIPPAGE: 0.005,      // assumed minimum 0.5% slippage (estimate)
  MAX_SLIPPAGE: 0.10,
  MIN_LIQUIDITY: 10000,      // refuse pools thinner than this (USD)
  MIN_NOTIONAL: 1,
  SL_MIN_PCT: 1, SL_MAX_PCT: 50,
  TP_MIN_PCT: 1, TP_MAX_PCT: 500,
  MONITOR_MAX_TRADES: 10,
  MONITOR_STALE_MS: 180000
};

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users(
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     username TEXT NOT NULL UNIQUE COLLATE NOCASE,
     pw_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS sessions(
     token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS paper_accounts(
     user_id INTEGER PRIMARY KEY, starting_balance REAL NOT NULL, cash REAL NOT NULL,
     open_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS paper_trades(
     id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, idem_key TEXT NOT NULL,
     net TEXT NOT NULL, pool TEXT NOT NULL, symbol TEXT,
     side TEXT NOT NULL DEFAULT 'LONG', status TEXT NOT NULL,
     qty REAL NOT NULL, entry_price REAL NOT NULL, entry_fill REAL NOT NULL, entry_price_ts INTEGER NOT NULL,
     stop_loss REAL NOT NULL, take_profit REAL NOT NULL, notional REAL NOT NULL, entry_fee REAL NOT NULL,
     entry_slippage REAL NOT NULL, max_planned_loss REAL NOT NULL,
     reason_open TEXT, opened_by TEXT NOT NULL DEFAULT 'user', opened_at INTEGER NOT NULL,
     exit_price REAL, exit_fill REAL, exit_price_ts INTEGER, exit_fee REAL, exit_slippage REAL,
     realized_pnl REAL, close_code TEXT, reason_close TEXT, closed_at INTEGER,
     UNIQUE(user_id, idem_key))`,
  `CREATE INDEX IF NOT EXISTS idx_trades_user_status ON paper_trades(user_id, status)`,
  `CREATE INDEX IF NOT EXISTS idx_trades_status ON paper_trades(status)`,
  `CREATE TABLE IF NOT EXISTS notifications(
     id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
     title TEXT NOT NULL, body TEXT, created_at INTEGER NOT NULL, is_read INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_notes_user ON notifications(user_id, created_at)`,
  `CREATE TABLE IF NOT EXISTS rate_limits(
     key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)`
];

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */
class ApiError extends Error {
  constructor(status, code, message, extra) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra || null;
  }
}

function jsonResponse(data, status, headers) {
  const h = new Headers(headers || {});
  h.set('Content-Type', 'application/json; charset=utf-8');
  h.set('Cache-Control', 'no-store');
  h.set('X-Content-Type-Options', 'nosniff');
  return new Response(JSON.stringify(data), { status: status || 200, headers: h });
}
const ok = (data, status, headers) => jsonResponse({ ok: true, data }, status, headers);

function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
const r6 = (x) => Math.round(x * 1e6) / 1e6;
const usd = (x) => (x < 0 ? '-$' : '$') + Math.abs(x).toFixed(2);

const enc = new TextEncoder();
function b64(buf) {
  let s = '';
  const a = new Uint8Array(buf);
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s);
}
function unb64(s) {
  const bin = atob(s);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}
function randB64(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64(a);
}
async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function hashPassword(pw, saltB64) {
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: unb64(saltB64), iterations: 100000 }, key, 256);
  return b64(bits);
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function getCookie(request, name) {
  const c = request.headers.get('Cookie') || '';
  const parts = c.split(';');
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].trim();
    if (p.indexOf(name + '=') === 0) return p.slice(name.length + 1);
  }
  return null;
}
function sessionCookie(token, maxAge) {
  return 'mp_session=' + token + '; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=' + maxAge;
}

let schemaReady = null;
function ensureSchema(env) {
  if (!schemaReady) {
    schemaReady = env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s))).catch((e) => {
      schemaReady = null;
      throw e;
    });
  }
  return schemaReady;
}

async function rateLimit(env, key, max, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare('SELECT window_start, count FROM rate_limits WHERE key=?').bind(key).first();
  if (!row || now - row.window_start >= windowSec) {
    await env.DB.prepare(
      'INSERT INTO rate_limits(key, window_start, count) VALUES(?,?,1) ' +
      'ON CONFLICT(key) DO UPDATE SET window_start=excluded.window_start, count=1').bind(key, now).run();
    return true;
  }
  if (row.count >= max) return false;
  await env.DB.prepare('UPDATE rate_limits SET count=count+1 WHERE key=?').bind(key).run();
  return true;
}

async function getMeta(env, key) {
  const r = await env.DB.prepare('SELECT value FROM meta WHERE key=?').bind(key).first();
  return r ? r.value : null;
}
async function setMeta(env, key, value) {
  await env.DB.prepare(
    'INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(key, value).run();
}
async function notify(env, userId, type, title, body) {
  await env.DB.prepare(
    'INSERT INTO notifications(user_id,type,title,body,created_at) VALUES(?,?,?,?,?)')
    .bind(userId, type, title, body || null, Date.now()).run();
}

/* ------------------------------------------------------------------ */
/* market data (GeckoTerminal, read-only, server side)                 */
/* ------------------------------------------------------------------ */
async function gt(path) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  try {
    const r = await fetch(GT + path, {
      headers: { Accept: 'application/json;version=20230302' },
      signal: ctrl.signal
    });
    if (r.status === 429) throw new ApiError(503, 'PROVIDER_RATE_LIMIT', 'GeckoTerminal rate limit reached. Try again in a minute.');
    if (r.status === 404) throw new ApiError(404, 'POOL_NOT_FOUND', 'That pool was not found on GeckoTerminal.');
    if (!r.ok) throw new ApiError(502, 'PROVIDER_ERROR', 'GeckoTerminal returned error ' + r.status + '.');
    return await r.json();
  } catch (e) {
    if (e instanceof ApiError) throw e;
    if (e && e.name === 'AbortError') throw new ApiError(504, 'PROVIDER_TIMEOUT', 'GeckoTerminal took too long to respond.');
    throw new ApiError(502, 'PROVIDER_UNREACHABLE', 'Could not reach GeckoTerminal.');
  } finally {
    clearTimeout(timer);
  }
}

function validatePool(net, pool) {
  if (CHAINS.indexOf(net) < 0) throw new ApiError(400, 'BAD_CHAIN', 'Unsupported blockchain.');
  const good = net === 'solana'
    ? /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(pool)
    : /^0x[a-fA-F0-9]{40}$/.test(pool);
  if (!good) throw new ApiError(400, 'BAD_POOL', 'That pool address is not valid for this blockchain.');
}

async function livePool(net, pool) {
  validatePool(net, pool);
  const j = await gt('/networks/' + net + '/pools/' + pool);
  const a = j && j.data && j.data.attributes;
  if (!a) throw new ApiError(502, 'PROVIDER_ERROR', 'GeckoTerminal sent no data for this pool.');
  const price = num(a.base_token_price_usd);
  if (!(price > 0)) throw new ApiError(502, 'PRICE_UNAVAILABLE', 'No valid live price is available for this pool.');
  return {
    price,
    liq: num(a.reserve_in_usd),
    pair: a.name || null,
    symbol: String(a.name || '?').split(' / ')[0].trim().slice(0, 24) || '?',
    fetched_at: Date.now()
  };
}

const keyOf = (net, pool) => net + ':' + String(pool).toLowerCase();

// Fetch live prices for many open trades, one request per chain (max 30 pools per request).
async function fetchMulti(trades) {
  const map = {};
  const errors = [];
  const byNet = {};
  trades.forEach((t) => {
    byNet[t.net] = byNet[t.net] || {};
    byNet[t.net][String(t.pool).toLowerCase()] = t.pool;
  });
  for (const net of Object.keys(byNet)) {
    const addrs = Object.keys(byNet[net]).map((k) => byNet[net][k]);
    for (let i = 0; i < addrs.length; i += 30) {
      const chunk = addrs.slice(i, i + 30);
      try {
        const j = await gt('/networks/' + net + '/pools/multi/' + chunk.join(','));
        (j.data || []).forEach((p) => {
          const a = p.attributes || {};
          const price = num(a.base_token_price_usd);
          if (a.address && price > 0) map[keyOf(net, a.address)] = { price, liq: num(a.reserve_in_usd) };
        });
      } catch (e) {
        errors.push(net + ': ' + (e.message || 'failed'));
      }
    }
  }
  return { map, errors };
}

/* ------------------------------------------------------------------ */
/* paper-trading maths (all costs are estimates and labelled as such)  */
/* ------------------------------------------------------------------ */
function slippageFor(notional, liq) {
  const impact = liq > 0 ? (2 * notional) / liq : LIMITS.MAX_SLIPPAGE;
  return Math.min(LIMITS.MAX_SLIPPAGE, Math.max(LIMITS.BASE_SLIPPAGE, impact));
}

function plan(price, liq, slPct, tpPct, notional) {
  const stop = price * (1 - slPct / 100);
  const target = price * (1 + tpPct / 100);
  const s = slippageFor(notional, liq);
  const entryFill = price * (1 + s);
  const entryFee = notional * LIMITS.FEE_RATE;
  const qty = notional / entryFill;
  const slProceeds = qty * stop * (1 - s);
  const slFee = slProceeds * LIMITS.FEE_RATE;
  const maxLoss = notional + entryFee - (slProceeds - slFee);
  const tpProceeds = qty * target * (1 - s);
  const tpFee = tpProceeds * LIMITS.FEE_RATE;
  const tpProfit = tpProceeds - tpFee - (notional + entryFee);
  return { price, stop, target, slippage: s, entryFill, entryFee, qty, maxLoss, tpProfit, notional };
}

function maxNotional(price, liq, slPct, tpPct, cap) {
  if (!(cap > 0)) return 0;
  if (plan(price, liq, slPct, tpPct, cap).maxLoss <= LIMITS.MAX_LOSS_PER_TRADE) return Math.floor(cap * 100) / 100;
  let lo = 0, hi = cap;
  for (let i = 0; i < 50; i++) {
    const mid = (lo + hi) / 2;
    if (plan(price, liq, slPct, tpPct, mid).maxLoss <= LIMITS.MAX_LOSS_PER_TRADE) lo = mid; else hi = mid;
  }
  return Math.floor(lo * 100) / 100;
}

function utcDayStart() {
  const d = new Date();
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}

async function getAccount(env, userId) {
  const a = await env.DB.prepare('SELECT * FROM paper_accounts WHERE user_id=?').bind(userId).first();
  if (!a) throw new ApiError(404, 'NO_ACCOUNT', 'Paper account not found.');
  return a;
}
async function dailyRealized(env, userId) {
  const r = await env.DB.prepare(
    "SELECT COALESCE(SUM(realized_pnl),0) v FROM paper_trades WHERE user_id=? AND status='CLOSED' AND closed_at>=?")
    .bind(userId, utcDayStart()).first();
  return r ? r.v : 0;
}

// Checks every rule. Used by both preview and open, so the two can never disagree.
async function evaluate(env, user, body) {
  const net = String(body.net || '');
  const pool = String(body.pool || '');
  validatePool(net, pool);
  const slPct = Number(body.sl_pct), tpPct = Number(body.tp_pct), notional = Number(body.notional);
  const violations = [];
  const bad = (code, message) => violations.push({ code, message });

  const inputsOk = { sl: true, tp: true, size: true };
  if (!Number.isFinite(slPct) || slPct < LIMITS.SL_MIN_PCT || slPct > LIMITS.SL_MAX_PCT) {
    inputsOk.sl = false;
    bad('STOP_LOSS_REQUIRED', 'A stop-loss is required: between ' + LIMITS.SL_MIN_PCT + '% and ' + LIMITS.SL_MAX_PCT + '% below the entry price.');
  }
  if (!Number.isFinite(tpPct) || tpPct < LIMITS.TP_MIN_PCT || tpPct > LIMITS.TP_MAX_PCT) {
    inputsOk.tp = false;
    bad('TAKE_PROFIT_REQUIRED', 'A take-profit is required: between ' + LIMITS.TP_MIN_PCT + '% and ' + LIMITS.TP_MAX_PCT + '% above the entry price.');
  }
  if (!Number.isFinite(notional) || notional < LIMITS.MIN_NOTIONAL) {
    inputsOk.size = false;
    bad('SIZE_INVALID', 'Position size must be at least $' + LIMITS.MIN_NOTIONAL + '.');
  }

  const live = await livePool(net, pool);
  const acct = await getAccount(env, user.id);
  const dailyLoss = Math.max(0, -(await dailyRealized(env, user.id)));

  const liqOk = live.liq !== null && live.liq >= LIMITS.MIN_LIQUIDITY;
  if (live.liq === null) bad('LIQUIDITY_UNAVAILABLE', 'Liquidity is unavailable for this pool, so slippage cannot be estimated. Trade refused.');
  else if (!liqOk) bad('LIQUIDITY_TOO_LOW', 'Pool liquidity is ' + usd(live.liq) + ', below the $' + LIMITS.MIN_LIQUIDITY + ' minimum for paper trades.');
  if (acct.open_count >= LIMITS.MAX_OPEN) bad('MAX_OPEN_TRADES', 'You already have ' + LIMITS.MAX_OPEN + ' open paper trades. Close one first.');
  if (dailyLoss >= LIMITS.MAX_DAILY_LOSS) bad('DAILY_LOSS_LIMIT', 'Daily realized loss limit of $' + LIMITS.MAX_DAILY_LOSS + ' reached. No new trades until tomorrow (UTC).');

  let p = null, maxN = null;
  if (inputsOk.sl && inputsOk.tp && inputsOk.size && liqOk) {
    p = plan(live.price, live.liq, slPct, tpPct, notional);
    const cap = Math.max(0, Math.min(acct.cash / (1 + LIMITS.FEE_RATE), 100));
    maxN = maxNotional(live.price, live.liq, slPct, tpPct, cap);
    if (p.maxLoss > LIMITS.MAX_LOSS_PER_TRADE + 1e-9) {
      bad('LOSS_PER_TRADE', 'Planned loss at the stop is ' + usd(p.maxLoss) + ' including fees and slippage, above the $' + LIMITS.MAX_LOSS_PER_TRADE + ' limit. A size of about ' + usd(maxN) + ' or less fits.');
    }
    if (notional + p.entryFee > acct.cash + 1e-9) bad('INSUFFICIENT_CASH', 'Not enough virtual cash. Available: ' + usd(acct.cash) + '.');
    if (dailyLoss < LIMITS.MAX_DAILY_LOSS && dailyLoss + p.maxLoss > LIMITS.MAX_DAILY_LOSS + 1e-9) {
      bad('DAILY_LOSS_LIMIT', 'This trade could push today\'s realized loss past the $' + LIMITS.MAX_DAILY_LOSS + ' daily limit (already lost ' + usd(dailyLoss) + ' today).');
    }
  }
  return { net, pool, live, acct, plan: p, maxNotional: maxN, dailyLoss, violations, slPct, tpPct, notional };
}

function previewView(ev) {
  const p = ev.plan;
  return {
    pair: ev.live.pair,
    symbol: ev.live.symbol,
    price: ev.live.price,
    price_fetched_at: ev.live.fetched_at,
    liquidity: ev.live.liq,
    stop_loss: p ? p.stop : null,
    take_profit: p ? p.target : null,
    assumed_fill: p ? p.entryFill : null,
    slippage_pct: p ? p.slippage * 100 : null,
    entry_fee: p ? p.entryFee : null,
    max_planned_loss: p ? p.maxLoss : null,
    profit_at_take_profit: p ? p.tpProfit : null,
    max_size_allowed: ev.maxNotional,
    cash: ev.acct.cash,
    daily_loss_so_far: ev.dailyLoss,
    violations: ev.violations,
    passes: ev.violations.length === 0
  };
}

async function openTrade(env, user, body) {
  const idem = String(body.idem_key || '');
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(idem)) throw new ApiError(400, 'BAD_IDEMPOTENCY_KEY', 'Missing request key. Refresh the page and try again.');
  const existing = await env.DB.prepare('SELECT * FROM paper_trades WHERE user_id=? AND idem_key=?').bind(user.id, idem).first();
  if (existing) return { duplicate: true, trade: existing };

  const ev = await evaluate(env, user, body);
  if (ev.violations.length) {
    throw new ApiError(422, 'RULES_FAILED', 'This paper trade breaks the risk rules, so it was not opened.', { violations: ev.violations });
  }
  const p = ev.plan, now = Date.now();
  const reason = String(body.reason || '').trim().slice(0, 200) || 'Manual paper trade';
  let tradeId;
  try {
    const ins = await env.DB.prepare(
      `INSERT INTO paper_trades(user_id,idem_key,net,pool,symbol,side,status,qty,entry_price,entry_fill,entry_price_ts,
         stop_loss,take_profit,notional,entry_fee,entry_slippage,max_planned_loss,reason_open,opened_by,opened_at)
       VALUES(?,?,?,?,?,'LONG','OPEN',?,?,?,?,?,?,?,?,?,?,?,'user',?)`)
      .bind(user.id, idem, ev.net, ev.pool, ev.live.symbol, p.qty, p.price, p.entryFill, ev.live.fetched_at,
        p.stop, p.target, p.notional, p.entryFee, p.slippage, p.maxLoss, reason, now).run();
    tradeId = ins.meta.last_row_id;
  } catch (e) {
    if (String(e && e.message).indexOf('UNIQUE') >= 0) {
      const again = await env.DB.prepare('SELECT * FROM paper_trades WHERE user_id=? AND idem_key=?').bind(user.id, idem).first();
      if (again) return { duplicate: true, trade: again };
    }
    throw e;
  }
  const cost = p.notional + p.entryFee;
  const upd = await env.DB.prepare(
    'UPDATE paper_accounts SET cash=cash-?, open_count=open_count+1 WHERE user_id=? AND cash>=? AND open_count<?')
    .bind(cost, user.id, cost, LIMITS.MAX_OPEN).run();
  if (upd.meta.changes !== 1) {
    await env.DB.prepare('DELETE FROM paper_trades WHERE id=?').bind(tradeId).run();
    throw new ApiError(409, 'LIMIT_REACHED', 'Another trade was opened at the same time and the limits no longer allow this one.');
  }
  await notify(env, user.id, 'paper_open', 'Paper trade opened: ' + ev.live.symbol,
    'Size ' + usd(p.notional) + ', entry ' + p.price + ', max planned loss ' + usd(p.maxLoss) + '.');
  const trade = await env.DB.prepare('SELECT * FROM paper_trades WHERE id=?').bind(tradeId).first();
  return { duplicate: false, trade };
}

// Closes an open trade at exitPrice. Shared by manual close and the monitor.
async function settle(env, t, exitPrice, liq, code, why) {
  const gross = t.qty * exitPrice;
  const s = liq ? slippageFor(gross, liq) : LIMITS.BASE_SLIPPAGE;
  const fill = exitPrice * (1 - s);
  const proceeds = t.qty * fill;
  const fee = proceeds * LIMITS.FEE_RATE;
  const net = proceeds - fee;
  const pnl = net - (t.notional + t.entry_fee);
  const now = Date.now();
  const u = await env.DB.prepare(
    `UPDATE paper_trades SET status='CLOSED', exit_price=?, exit_fill=?, exit_price_ts=?, exit_fee=?, exit_slippage=?,
       realized_pnl=?, close_code=?, reason_close=?, closed_at=? WHERE id=? AND status='OPEN'`)
    .bind(exitPrice, fill, now, fee, s, pnl, code, why, now, t.id).run();
  if (u.meta.changes !== 1) return null;
  await env.DB.prepare('UPDATE paper_accounts SET cash=cash+?, open_count=MAX(open_count-1,0) WHERE user_id=?').bind(net, t.user_id).run();
  const label = code === 'STOP_LOSS' ? 'Stop-loss hit' : code === 'TAKE_PROFIT' ? 'Take-profit hit' : 'Closed manually';
  await notify(env, t.user_id, code === 'STOP_LOSS' ? 'stop_loss' : code === 'TAKE_PROFIT' ? 'take_profit' : 'paper_close',
    label + ': ' + t.symbol, 'Realized PnL ' + usd(pnl) + '. ' + why);
  const daily = Math.max(0, -(await dailyRealized(env, t.user_id)));
  if (daily >= 2) {
    await notify(env, t.user_id, 'risk_warning', 'Daily loss warning',
      'Realized loss today is ' + usd(daily) + ' of the $' + LIMITS.MAX_DAILY_LOSS + ' daily limit.');
  }
  return { pnl, exit_fill: fill, fee, slippage: s };
}

async function closeTrade(env, user, body) {
  const id = Number(body.id);
  if (!Number.isInteger(id) || id <= 0) throw new ApiError(400, 'BAD_ID', 'Missing trade id.');
  const t = await env.DB.prepare("SELECT * FROM paper_trades WHERE id=? AND user_id=? AND status='OPEN'").bind(id, user.id).first();
  if (!t) throw new ApiError(404, 'NOT_OPEN', 'That trade is not open (it may already be closed).');
  const live = await livePool(t.net, t.pool);
  const res = await settle(env, t, live.price, live.liq, 'MANUAL', 'Closed manually at ' + live.price + '.');
  if (!res) throw new ApiError(409, 'ALREADY_CLOSED', 'That trade was just closed.');
  const closed = await env.DB.prepare('SELECT * FROM paper_trades WHERE id=?').bind(id).first();
  return { trade: closed };
}

/* ------------------------------------------------------------------ */
/* monitor (runs every minute from the cron trigger)                    */
/* ------------------------------------------------------------------ */
async function monitor(env) {
  await ensureSchema(env);
  let error = null;
  try {
    const open = (await env.DB.prepare("SELECT * FROM paper_trades WHERE status='OPEN' ORDER BY opened_at LIMIT ?")
      .bind(LIMITS.MONITOR_MAX_TRADES).all()).results || [];
    if (open.length) {
      const { map, errors } = await fetchMulti(open);
      if (errors.length) error = errors.join('; ');
      for (const t of open) {
        const q = map[keyOf(t.net, t.pool)];
        if (!q) { error = error || ('No live price for ' + t.symbol); continue; }
        try {
          if (q.price <= t.stop_loss) {
            await settle(env, t, q.price, q.liq, 'STOP_LOSS', 'Price ' + q.price + ' reached the stop-loss ' + t.stop_loss + '.');
          } else if (q.price >= t.take_profit) {
            await settle(env, t, t.take_profit, q.liq, 'TAKE_PROFIT', 'Price ' + q.price + ' reached the take-profit ' + t.take_profit + '.');
          }
        } catch (e) {
          error = (error ? error + '; ' : '') + 'Close failed for ' + t.symbol;
        }
      }
    }
  } catch (e) {
    error = String((e && e.message) || e);
  }
  const now = String(Date.now());
  await setMeta(env, 'monitor_last_run', now);
  if (!error) await setMeta(env, 'monitor_last_ok', now);
  await setMeta(env, 'monitor_last_error', error || '');
}

/* ------------------------------------------------------------------ */
/* auth                                                                */
/* ------------------------------------------------------------------ */
async function getUser(request, env) {
  const token = getCookie(request, 'mp_session');
  if (!token || token.length < 20) return null;
  const h = await sha256hex(token);
  const row = await env.DB.prepare(
    'SELECT u.id AS id, u.username AS username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?')
    .bind(h, Date.now()).first();
  return row || null;
}
async function requireUser(request, env) {
  const u = await getUser(request, env);
  if (!u) throw new ApiError(401, 'NOT_LOGGED_IN', 'Please log in first.');
  return u;
}
async function startSession(env, userId) {
  const token = randB64(32).replace(/[^A-Za-z0-9]/g, 'x');
  const exp = Date.now() + 30 * 86400000;
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(await sha256hex(token), userId, exp).run();
  return token;
}

async function register(request, env, body) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await rateLimit(env, 'reg:' + ip, 5, 3600))) throw new ApiError(429, 'RATE_LIMITED', 'Too many sign-ups from this connection. Try again later.');
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) throw new ApiError(400, 'BAD_USERNAME', 'Username must be 3 to 24 letters, numbers or underscores.');
  if (password.length < 8 || password.length > 128) throw new ApiError(400, 'BAD_PASSWORD', 'Password must be 8 to 128 characters.');
  const taken = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
  if (taken) throw new ApiError(409, 'USERNAME_TAKEN', 'That username is already taken.');
  const salt = randB64(16);
  const hash = await hashPassword(password, salt);
  const now = Date.now();
  let userId;
  try {
    const ins = await env.DB.prepare('INSERT INTO users(username,pw_hash,salt,created_at) VALUES(?,?,?,?)').bind(username, hash, salt, now).run();
    userId = ins.meta.last_row_id;
  } catch (e) {
    throw new ApiError(409, 'USERNAME_TAKEN', 'That username is already taken.');
  }
  await env.DB.prepare('INSERT INTO paper_accounts(user_id,starting_balance,cash,open_count,created_at) VALUES(?,?,?,0,?)')
    .bind(userId, LIMITS.START_BALANCE, LIMITS.START_BALANCE, now).run();
  await notify(env, userId, 'welcome', 'Paper account ready', 'Your virtual account starts at $' + LIMITS.START_BALANCE + '. No real money is ever used.');
  const token = await startSession(env, userId);
  return ok({ user: { username } }, 200, { 'Set-Cookie': sessionCookie(token, 2592000) });
}

async function login(request, env, body) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await rateLimit(env, 'login:' + ip, 15, 600))) throw new ApiError(429, 'RATE_LIMITED', 'Too many login attempts. Wait 10 minutes and try again.');
  const username = String(body.username || '').trim();
  const password = String(body.password || '');
  const row = await env.DB.prepare('SELECT id, username, pw_hash, salt FROM users WHERE username=?').bind(username).first();
  const salt = row ? row.salt : 'AAAAAAAAAAAAAAAAAAAAAA==';
  const hash = await hashPassword(password, salt);
  if (!row || !safeEqual(hash, row.pw_hash)) throw new ApiError(401, 'BAD_LOGIN', 'Wrong username or password.');
  const token = await startSession(env, row.id);
  return ok({ user: { username: row.username } }, 200, { 'Set-Cookie': sessionCookie(token, 2592000) });
}

async function logout(request, env) {
  const token = getCookie(request, 'mp_session');
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256hex(token)).run();
  return ok({ loggedOut: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
}

/* ------------------------------------------------------------------ */
/* account state, notifications, health                                 */
/* ------------------------------------------------------------------ */
async function accountState(env, user) {
  const acct = await getAccount(env, user.id);
  const open = (await env.DB.prepare("SELECT * FROM paper_trades WHERE user_id=? AND status='OPEN' ORDER BY opened_at DESC").bind(user.id).all()).results || [];
  const closed = (await env.DB.prepare("SELECT * FROM paper_trades WHERE user_id=? AND status='CLOSED' ORDER BY closed_at DESC LIMIT 50").bind(user.id).all()).results || [];
  const st = await env.DB.prepare(
    `SELECT COUNT(*) n, COALESCE(SUM(CASE WHEN realized_pnl>0 THEN 1 ELSE 0 END),0) wins,
            COALESCE(SUM(realized_pnl),0) pnl, COALESCE(SUM(entry_fee+COALESCE(exit_fee,0)),0) fees,
            AVG(CASE WHEN realized_pnl>0 THEN realized_pnl END) avg_win,
            AVG(CASE WHEN realized_pnl<=0 THEN realized_pnl END) avg_loss,
            MAX(realized_pnl) best, MIN(realized_pnl) worst
     FROM paper_trades WHERE user_id=? AND status='CLOSED'`).bind(user.id).first();
  const curveRows = (await env.DB.prepare(
    "SELECT closed_at, realized_pnl FROM paper_trades WHERE user_id=? AND status='CLOSED' ORDER BY closed_at ASC LIMIT 500").bind(user.id).all()).results || [];
  let running = acct.starting_balance;
  const curve = [{ t: acct.created_at, v: running }];
  curveRows.forEach((r) => { running += r.realized_pnl; curve.push({ t: r.closed_at, v: r64(running) }); });
  const daily = await dailyRealized(env, user.id);
  const unread = await env.DB.prepare('SELECT COUNT(*) n FROM notifications WHERE user_id=? AND is_read=0').bind(user.id).first();

  let priceMap = {}, priceErrors = [];
  if (open.length) {
    const m = await fetchMulti(open);
    priceMap = m.map;
    priceErrors = m.errors;
  }
  let openCost = 0, openValue = 0, unrealized = 0, valueKnown = true;
  const openOut = open.map((t) => {
    const q = priceMap[keyOf(t.net, t.pool)];
    openCost += t.notional + t.entry_fee;
    let now = null, unr = null;
    if (q) {
      now = q.price;
      unr = t.qty * q.price - t.notional - t.entry_fee;
      openValue += t.qty * q.price;
      unrealized += unr;
    } else {
      valueKnown = false;
    }
    return Object.assign({}, t, { current_price: now, unrealized_pnl: unr });
  });

  const lastRun = Number(await getMeta(env, 'monitor_last_run')) || null;
  const lastOk = Number(await getMeta(env, 'monitor_last_ok')) || null;
  const lastErr = (await getMeta(env, 'monitor_last_error')) || '';
  const active = !!(lastOk && Date.now() - lastOk < LIMITS.MONITOR_STALE_MS);

  const n = st.n || 0;
  return {
    account: {
      starting_balance: acct.starting_balance,
      cash: acct.cash,
      open_positions_cost: openCost,
      open_positions_value: valueKnown ? openValue : null,
      account_value: valueKnown ? acct.cash + openValue : null,
      unrealized_pnl: valueKnown ? unrealized : null,
      realized_pnl: st.pnl,
      estimated_fees_paid: st.fees,
      realized_today: daily,
      open_count: acct.open_count
    },
    stats: {
      total_closed: n,
      wins: st.wins,
      win_rate: n ? (st.wins / n) * 100 : null,
      avg_win: st.avg_win,
      avg_loss: st.avg_loss,
      best: st.best,
      worst: st.worst
    },
    open: openOut,
    closed,
    curve,
    unread_notifications: unread ? unread.n : 0,
    monitoring: {
      active,
      last_ok: lastOk,
      last_run: lastRun,
      last_error: lastErr || (priceErrors.length ? priceErrors.join('; ') : ''),
      note: active
        ? 'Stop-loss and take-profit are checked about once a minute. A fast spike between checks can be missed.'
        : 'Automatic monitoring is NOT confirmed active right now, so stops and targets are not being watched. Close positions manually if needed.'
    },
    limits: {
      max_loss_per_trade: LIMITS.MAX_LOSS_PER_TRADE,
      max_daily_loss: LIMITS.MAX_DAILY_LOSS,
      max_open: LIMITS.MAX_OPEN,
      fee_rate: LIMITS.FEE_RATE,
      base_slippage: LIMITS.BASE_SLIPPAGE,
      min_liquidity: LIMITS.MIN_LIQUIDITY
    }
  };
}
function r64(x) { return Math.round(x * 1e6) / 1e6; }

let providerCache = { t: 0, ok: null, msg: '' };
async function providerCheck() {
  if (Date.now() - providerCache.t < 60000) return providerCache;
  try {
    await gt('/networks?page=1');
    providerCache = { t: Date.now(), ok: true, msg: 'Responding' };
  } catch (e) {
    providerCache = { t: Date.now(), ok: false, msg: e.message || 'Failed' };
  }
  return providerCache;
}

async function health(env) {
  let dbOk = false, dbMsg = '';
  try { await env.DB.prepare('SELECT 1').first(); dbOk = true; } catch (e) { dbMsg = 'Database query failed'; }
  const prov = await providerCheck();
  let lastRun = null, lastOk = null, lastErr = '';
  if (dbOk) {
    lastRun = Number(await getMeta(env, 'monitor_last_run')) || null;
    lastOk = Number(await getMeta(env, 'monitor_last_ok')) || null;
    lastErr = (await getMeta(env, 'monitor_last_error')) || '';
  }
  const monitorActive = !!(lastOk && Date.now() - lastOk < LIMITS.MONITOR_STALE_MS);
  return {
    time: Date.now(),
    backend: { ok: true },
    database: { ok: dbOk, message: dbMsg },
    market_data: { provider: 'GeckoTerminal', ok: prov.ok, message: prov.msg, checked_at: prov.t },
    paper_trading: { ok: dbOk, message: dbOk ? 'Engine running with server-side risk rules' : 'Database unavailable' },
    monitoring: { active: monitorActive, last_run: lastRun, last_ok: lastOk, last_error: lastErr },
    ai_agents: { available: [], failed: [], message: 'AI agents are not built yet. They arrive in the next stage.' },
    keys: {
      gemini: !!env.GEMINI_API_KEY,
      exa: !!env.EXA_API_KEY,
      helius: !!env.HELIUS_API_KEY
    }
  };
}

/* ------------------------------------------------------------------ */
/* router                                                              */
/* ------------------------------------------------------------------ */
async function readBody(request) {
  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > 10000) throw new ApiError(413, 'TOO_LARGE', 'Request too large.');
  const ct = request.headers.get('Content-Type') || '';
  if (ct.indexOf('application/json') < 0) throw new ApiError(415, 'BAD_CONTENT_TYPE', 'Requests must be JSON.');
  try {
    const b = await request.json();
    return b && typeof b === 'object' ? b : {};
  } catch (e) {
    throw new ApiError(400, 'BAD_JSON', 'Request body is not valid JSON.');
  }
}

async function route(request, env, url) {
  const method = request.method;
  const path = url.pathname.replace(/\/+$/, '') || '/';

  if (method !== 'GET' && method !== 'HEAD') {
    const origin = request.headers.get('Origin');
    if (origin && origin !== url.origin) throw new ApiError(403, 'BAD_ORIGIN', 'Cross-site requests are not allowed.');
  }

  await ensureSchema(env);

  if (method === 'GET' && path === '/api/health') return ok(await health(env));

  if (method === 'GET' && path === '/api/auth/me') {
    const u = await getUser(request, env);
    return ok({ user: u ? { username: u.username } : null });
  }
  if (method === 'POST' && path === '/api/auth/register') return register(request, env, await readBody(request));
  if (method === 'POST' && path === '/api/auth/login') return login(request, env, await readBody(request));
  if (method === 'POST' && path === '/api/auth/logout') return logout(request, env);

  if (path.indexOf('/api/paper') === 0 || path.indexOf('/api/notifications') === 0) {
    const user = await requireUser(request, env);

    if (method === 'GET' && path === '/api/paper/account') return ok(await accountState(env, user));

    if (method === 'POST' && path === '/api/paper/preview') {
      if (!(await rateLimit(env, 'prev:' + user.id, 30, 60))) throw new ApiError(429, 'RATE_LIMITED', 'Slow down a little and try again.');
      const ev = await evaluate(env, user, await readBody(request));
      return ok(previewView(ev));
    }
    if (method === 'POST' && path === '/api/paper/trade/open') {
      if (!(await rateLimit(env, 'trade:' + user.id, 20, 60))) throw new ApiError(429, 'RATE_LIMITED', 'Slow down a little and try again.');
      return ok(await openTrade(env, user, await readBody(request)));
    }
    if (method === 'POST' && path === '/api/paper/trade/close') {
      if (!(await rateLimit(env, 'trade:' + user.id, 20, 60))) throw new ApiError(429, 'RATE_LIMITED', 'Slow down a little and try again.');
      return ok(await closeTrade(env, user, await readBody(request)));
    }
    if (method === 'GET' && path === '/api/paper/trades') {
      const rows = (await env.DB.prepare('SELECT * FROM paper_trades WHERE user_id=? ORDER BY opened_at DESC LIMIT 200').bind(user.id).all()).results || [];
      return ok({ trades: rows });
    }
    if (method === 'GET' && path === '/api/notifications') {
      const rows = (await env.DB.prepare('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50').bind(user.id).all()).results || [];
      return ok({ notifications: rows });
    }
    if (method === 'POST' && path === '/api/notifications/read-all') {
      await env.DB.prepare('UPDATE notifications SET is_read=1 WHERE user_id=?').bind(user.id).run();
      return ok({ done: true });
    }
  }

  throw new ApiError(404, 'NOT_FOUND', 'Unknown endpoint.');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.indexOf('/api/') !== 0) return env.ASSETS.fetch(request);
    try {
      return await route(request, env, url);
    } catch (e) {
      if (e instanceof ApiError) {
        return jsonResponse({ ok: false, error: Object.assign({ code: e.code, message: e.message }, e.extra || {}) }, e.status);
      }
      console.error('Unhandled error', e && e.stack ? e.stack : e);
      return jsonResponse({ ok: false, error: { code: 'SERVER_ERROR', message: 'Something went wrong on the server. Try again in a moment.' } }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(monitor(env));
  }
};
