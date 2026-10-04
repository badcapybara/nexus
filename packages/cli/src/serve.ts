import { createServer } from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import { listFindings, type Finding } from "@nexus/core";

const MIME: Record<string, string> = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".svg": "image/svg+xml",
};

export async function serveDashboard(runDir: string, port: number): Promise<void> {
  const webDist = new URL("../../web/dist", import.meta.url).pathname;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${port}`);

    if (url.pathname === "/api/findings") {
      const findings = await listFindings(runDir);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ findings }));
      return;
    }
    if (url.pathname.startsWith("/api/findings/")) {
      const id = url.pathname.split("/").pop();
      const findings = await listFindings(runDir);
      const f: Finding | undefined = findings.find((x) => x.id === id);
      if (!f) {
        res.writeHead(404).end("not found");
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(f));
      return;
    }
    if (url.pathname === "/api/config") {
      try {
        const raw = await fs.readFile(path.join(runDir, "nexus.config.json"), "utf8");
        res.writeHead(200, { "content-type": "application/json" }).end(raw);
      } catch {
        res.writeHead(404).end("{}");
      }
      return;
    }

    // static
    let file = url.pathname === "/" ? "/index.html" : url.pathname;
    const abs = path.join(webDist, file);
    if (!abs.startsWith(webDist)) {
      res.writeHead(403).end();
      return;
    }
    try {
      const data = await fs.readFile(abs);
      res.writeHead(200, { "content-type": MIME[path.extname(abs)] ?? "application/octet-stream" });
      res.end(data);
    } catch {
      res.writeHead(404).end("not found");
    }
  });

  server.listen(port, () => {
    console.log(`NEXUS dashboard → http://localhost:${port}`);
    console.log(`serving findings from ${runDir}`);
  });
}
