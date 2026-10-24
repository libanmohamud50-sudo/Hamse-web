const enc = new TextEncoder();
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));

async function hp(pw, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unhex(salt), iterations: 100000 }, k, 256));
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function body(req) {
  try { const t = await req.text(); return t.length > 4096 ? {} : JSON.parse(t || "{}"); } catch { return {}; }
}
function token() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function me(req, env) {
  const t = (req.headers.get("authorization") || "").replace("Bearer ", "");
  return [t ? await env.USERS.get("s:" + t) : null, t];
}
async function bump(env, key, ttl) {
  const n = parseInt((await env.USERS.get(key)) || "0", 10) + 1;
  await env.USERS.put(key, String(n), { expirationTtl: ttl });
  return n;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    const ip = req.headers.get("cf-connecting-ip") || "x";

    if (url.pathname === "/api/me" && req.method === "GET") {
      const [u] = await me(req, env);
      return u ? json({ username: u }) : json({ error: "Sign in first." }, 401);
    }
    if (req.method !== "POST") return json({ error: "Not found." }, 404);

    if (url.pathname === "/api/register") {
      const d = await body(req);
      const u = String(d.username || "").trim().toLowerCase();
      const p = String(d.password || "");
      if (!/^[a-z0-9_.]{3,30}$/.test(u)) return json({ error: "Username: 3-30 letters, numbers, _ or ." }, 400);
      if (p.length < 6) return json({ error: "Password must have at least 6 characters." }, 400);
      if (parseInt((await env.USERS.get("r:" + ip)) || "0", 10) >= 10) return json({ error: "Too many new accounts. Try later." }, 429);
      if (await env.USERS.get("u:" + u)) return json({ error: "This username is taken. Choose another one." }, 409);
      const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
      await env.USERS.put("u:" + u, JSON.stringify({ salt, hash: await hp(p, salt), created: Date.now() }));
      await bump(env, "r:" + ip, 3600);
      return json({ ok: true });
    }
    if (url.pathname === "/api/login") {
      const d = await body(req);
      if (parseInt((await env.USERS.get("f:" + ip)) || "0", 10) >= 8) return json({ error: "Too many tries. Wait 10 minutes." }, 429);
      const u = String(d.username || "").trim().toLowerCase();
      const p = String(d.password || "");
      const raw = /^[a-z0-9_.]{3,30}$/.test(u) ? await env.USERS.get("u:" + u) : null;
      if (raw) {
        const rec = JSON.parse(raw);
        if (same(rec.hash, await hp(p, rec.salt))) {
          const t = token();
          await env.USERS.put("s:" + t, u, { expirationTtl: 60 * 60 * 24 * 30 });
          await env.USERS.delete("f:" + ip);
          return json({ token: t, username: u });
        }
      }
      await bump(env, "f:" + ip, 600);
      return json({ error: "Wrong username or password." }, 401);
    }
    if (url.pathname === "/api/logout") {
      const [, t] = await me(req, env);
      if (t) await env.USERS.delete("s:" + t);
      return json({ ok: true });
    }
    return json({ error: "Not found." }, 404);
  },
};
