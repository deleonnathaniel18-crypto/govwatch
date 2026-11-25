export default {
  async fetch(request, env) {
    if (!env.PROBE_KEY || request.headers.get("X-Probe-Key") !== env.PROBE_KEY) {
      return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    const reqUrl = new URL(request.url);
    const target = reqUrl.searchParams.get("url") || "";
    let method = (reqUrl.searchParams.get("method") || "HEAD").toUpperCase();
    if (method !== "HEAD" && method !== "GET") method = "HEAD";

    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      return Response.json({ error: "Invalid URL" }, { status: 400 });
    }

    if (parsed.protocol !== "https:" || !parsed.hostname.toLowerCase().endsWith(".gov.ph")) {
      return Response.json({ error: "Only https://*.gov.ph URLs are allowed" }, { status: 403 });
    }

    const headers = {
      "User-Agent": "GovSourceWatch/1.0 (+https://github.com/govsource-watch; civic-tech-observatory)",
      Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9",
    };

    const runProbe = async (m) => {
      const start = Date.now();
      const resp = await fetch(target, {
        method: m,
        headers,
        redirect: "follow",
        signal: AbortSignal.timeout(15000),
      });
      const latencyMs = Date.now() - start;
      let snippet = "";
      if (m === "GET" && (resp.status === 403 || resp.status === 429)) {
        snippet = (await resp.text()).slice(0, 4096);
      }
      return {
        http_status: resp.status,
        response_time_ms: latencyMs,
        etag: resp.headers.get("etag"),
        last_modified: resp.headers.get("last-modified"),
        headers: Object.fromEntries(resp.headers.entries()),
        snippet,
      };
    };

    try {
      let result = await runProbe(method);
      if (method === "HEAD" && [400, 403, 405].includes(result.http_status)) {
        result = await runProbe("GET");
      }
      return Response.json(result);
    } catch (err) {
      if (method === "HEAD") {
        try {
          const fallback = await runProbe("GET");
          return Response.json(fallback);
        } catch (err2) {
          return Response.json({ error: err2?.name || "FetchError" }, { status: 502 });
        }
      }
      return Response.json({ error: err?.name || "FetchError" }, { status: 502 });
    }
  },
};
