// Bundles the extension into dist/, which is what gets loaded unpacked or zipped.
//
// esbuild rather than a framework: two entry points and no JSX is not a build problem, and
// a smaller toolchain is a smaller thing to keep working across a store review cycle.

import { build } from "esbuild";
import { copyFileSync, cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Every path below is relative to this file, so the build does not depend on where it was
// invoked from. npm --prefix does not change the working directory.
process.chdir(dirname(fileURLToPath(import.meta.url)));

mkdirSync("dist", { recursive: true });

await build({
  entryPoints: ["src/background.ts", "src/dashboard.ts"],
  bundle: true,
  format: "esm",
  // The manifest's minimum_chrome_version. Keeping the two in step means a syntax the
  // stated minimum cannot parse is a build error rather than a support ticket.
  target: "chrome116",
  outdir: "dist",
  // Nothing here is injected into a page any more, so this is a few kilobytes either way.
  // Kept because a store reviewer reads what is shipped, and two builds of the same source
  // should produce the same bytes.
  minify: true,
  logLevel: "info",
});

for (const file of ["manifest.json", "dashboard.html"]) {
  copyFileSync(file, `dist/${file}`);
}

// The manifest names these, so a build without them is a broken extension rather than a
// plain one. Saying so here beats a puzzle-piece icon and a console warning at load time.
if (!existsSync("icons")) {
  throw new Error("no icons/ — run: npm --prefix extension run icons");
}
cpSync("icons", "dist/icons", { recursive: true });
