// Bundles the extension into dist/, which is what gets loaded unpacked or zipped.
//
// esbuild rather than a framework: two entry points and no JSX is not a build problem, and
// a smaller toolchain is a smaller thing to keep working across a store review cycle.

import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Every path below is relative to this file, so the build does not depend on where it was
// invoked from. npm --prefix does not change the working directory.
process.chdir(dirname(fileURLToPath(import.meta.url)));

mkdirSync("dist", { recursive: true });

await build({
  entryPoints: ["src/background.ts", "src/panel.ts"],
  bundle: true,
  format: "esm",
  // The manifest's minimum_chrome_version. Keeping the two in step means a syntax the
  // stated minimum cannot parse is a build error rather than a support ticket.
  target: "chrome116",
  outdir: "dist",
  logLevel: "info",
});

for (const file of ["manifest.json", "panel.html"]) {
  copyFileSync(file, `dist/${file}`);
}
