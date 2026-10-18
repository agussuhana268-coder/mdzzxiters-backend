/**
 * MDZZXITERS stable API front door (Cloudflare Workers).
 *
 * Configure BACKEND_ORIGIN as a Worker variable, e.g.
 * https://mdzzxiters-backend-production-1db4.up.railway.app
 *
 * This is a compatibility proxy, not an independent license backend:
 * requests still depend on the upstream Railway service.
 */
const ALLOWED_PATHS = new Set([
  "/api/health",
  "/api/licenses/activate",
  "/api/licenses/check",
  "/api/licenses/session",
]);

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function json(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders(origin),
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (!ALLOWED_PATHS.has(url.pathname)) {
      return json({ success: false, code: "not_found" }, 404, origin);
    }

    if (!["GET", "POST"].includes(request.method)) {
      return json({ success: false, code: "method_not_allowed" }, 405, origin);
    }

    const backendOrigin = String(env.BACKEND_ORIGIN || "").trim().replace(/\/+$/, "");
    if (!backendOrigin) {
      return json({ success: false, code: "backend_not_configured" }, 503, origin);
    }

    let upstream;
    try {
      const target = new URL(backendOrigin);
      if (target.protocol !== "https:") {
        return json({ success: false, code: "invalid_backend_config" }, 500, origin);
      }
      target.pathname = url.pathname;
      target.search = url.search;

      const headers = new Headers(request.headers);
      headers.delete("host");
      headers.delete("content-length");
      headers.delete("cf-connecting-ip");
      headers.delete("cf-ray");

      upstream = await fetch(target.toString(), {
        method: request.method,
        headers,
        body: request.method === "GET" ? undefined : request.body,
        redirect: "manual",
      });
    } catch (_) {
      return json({ success: false, code: "backend_unavailable" }, 502, origin);
    }

    const responseHeaders = new Headers(upstream.headers);
    for (const [key, value] of Object.entries(corsHeaders(origin))) {
      responseHeaders.set(key, value);
    }
    responseHeaders.set("Cache-Control", "no-store");

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  },
};
