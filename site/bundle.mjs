// Bundle the browser scripts of kube-noob.com: `node bundle.mjs <out-dir>` writes <out-dir>/assets/*.js.
import { build } from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(process.argv[2] ?? path.join(here, "..", "_site"));
const assets = path.join(out, "assets");
fs.mkdirSync(assets, { recursive: true });

await build({
  entryPoints: {
    site: path.join(here, "src", "site.js"),
    playground: path.join(here, "src", "playground.js"),
    agent: path.join(here, "src", "agent.js"),
  },
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  minify: true,
  sourcemap: false,
  legalComments: "linked",
  outdir: assets,
  logLevel: "info",
});
fs.copyFileSync(path.join(here, "node_modules", "mermaid", "dist", "mermaid.min.js"), path.join(assets, "mermaid.min.js"));
console.log(`bundled into ${assets}`);
