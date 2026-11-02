// وصّلني — إرسال إشعارات FCM. تُستدعى من قاعدة البيانات فقط (سر مشترك). لا مفاتيح داخل الكود.
import { createClient } from "npm:@supabase/supabase-js@2";

const SA = JSON.parse(Deno.env.get("FCM_SERVICE_ACCOUNT") ?? "{}");
const SECRET = Deno.env.get("PUSH_WEBHOOK_SECRET") ?? "";
const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

const b64u = (b: ArrayBuffer | string) =>
  btoa(typeof b === "string" ? b : String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

let cached: { t: string; exp: number } | null = null;
async function accessToken(): Promise<string> {
  if (cached && cached.exp > Date.now() + 60_000) return cached.t;
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64u(JSON.stringify({ iss: SA.client_email, scope: "https://www.googleapis.com/auth/firebase.messaging", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const pem = String(SA.private_key).replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(head + "." + claim));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + head + "." + claim + "." + b64u(sig),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("fcm auth failed");
  cached = { t: j.access_token, exp: Date.now() + (j.expires_in ?? 3600) * 1000 };
  return cached.t;
}

Deno.serve(async (req) => {
  if (!SECRET || req.headers.get("x-webhook-secret") !== SECRET) return new Response("forbidden", { status: 403 });
  let id: number;
  try { id = Number((await req.json()).id); } catch { return new Response("bad", { status: 400 }); }
  const { data: n } = await db.from("notif_log").select("*").eq("id", id).maybeSingle();
  if (!n || n.sent_at) return new Response("skip");
  // نحجز الإشعار أولاً حتى لا يُرسل مرتين
  const { data: claimed } = await db.from("notif_log").update({ sent_at: new Date().toISOString() }).eq("id", id).is("sent_at", null).select("id");
  if (!claimed || !claimed.length) return new Response("dup");

  const rcpt = String(n.recipient), ix = rcpt.indexOf(":");
  const role = ix < 0 ? rcpt : rcpt.slice(0, ix), key = ix < 0 ? "admin" : rcpt.slice(ix + 1);
  const { data: rows } = await db.from("push_tokens").select("token").eq("role", role).eq("key", key);
  const tokens = [...new Set((rows ?? []).map((r) => r.token as string))];
  if (!tokens.length) return new Response("no tokens");

  const at = await accessToken();
  const url = `https://fcm.googleapis.com/v1/projects/${SA.project_id}/messages:send`;
  const dead: string[] = [];
  await Promise.all(tokens.map(async (token) => {
    const r = await fetch(url, {
      method: "POST", headers: { Authorization: "Bearer " + at, "Content-Type": "application/json" },
      body: JSON.stringify({ message: {
        token,
        notification: { title: n.title, body: n.body },
        data: { order_id: String(n.order_id ?? ""), kind: String(n.kind), role },
        android: { priority: "HIGH", ttl: "3600s", notification: { channel_id: "orders", icon: "ic_stat_wasselni", color: "#F26A1B", tag: String(n.dedupe), sound: "default" } },
      } }),
    });
    if (!r.ok) { const t = await r.text(); if (r.status === 404 || /UNREGISTERED|INVALID_ARGUMENT/.test(t)) dead.push(token); }
  }));
  if (dead.length) await db.from("push_tokens").delete().in("token", dead);
  return new Response("ok");
});
