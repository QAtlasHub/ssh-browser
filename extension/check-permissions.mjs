// The extension's reach, checked against what is written down.
//
//   node extension/check-permissions.mjs          # compare
//   node extension/check-permissions.mjs --write  # accept the manifest as the new pin
//
// Every key here decides what the extension can touch: which APIs it may call, which origins
// it may talk to, which pages it may be injected into, and which of its own pages the web may
// open. Those are the questions a reviewer asks, and they are the ones that change by
// accident — a key added while fixing something else looks like nothing in a diff full of
// TypeScript. This makes such a change fail CI until it is written down beside the reason.

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// Absent and empty are the same answer to "what can it reach", so they are normalised to one.
// Otherwise dropping the last entry of a list would read as a change and adding the first
// would not.
const KEYS = [
  "permissions",
  "host_permissions",
  "optional_permissions",
  "optional_host_permissions",
  "content_scripts",
  "web_accessible_resources",
];
const SCALARS = ["externally_connectable", "content_security_policy"];

/// Sorted, so reordering a list is not a finding. What it can reach is a set, not a sequence.
function normalise(value) {
  if (Array.isArray(value)) return value.map(normalise).sort(compare);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => compare(a, b))
        .map(([k, v]) => [k, normalise(v)]),
    );
  }
  return value;
}

const compare = (a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1);

const manifest = JSON.parse(await readFile(join(here, "manifest.json"), "utf8"));
const surface = {};
for (const key of KEYS) surface[key] = normalise(manifest[key] ?? []);
for (const key of SCALARS) surface[key] = normalise(manifest[key] ?? null);

const pinPath = join(here, "permissions.json");
const pinned = JSON.parse(await readFile(pinPath, "utf8"));
const { _comment: why, ...expected } = pinned;

if (process.argv.includes("--write")) {
  await writeFile(pinPath, `${JSON.stringify({ _comment: why, ...surface }, null, 2)}\n`);
  console.log("extension/permissions.json rewritten from the manifest");
  process.exit(0);
}

// Both sides through the same normalisation, key order included: the pin is a set of
// answers, and which order they were written in is not one of them.
const got = JSON.stringify(normalise(surface), null, 2);
const want = JSON.stringify(normalise(expected), null, 2);
if (got === want) {
  console.log("the extension reaches exactly what extension/permissions.json says");
  process.exit(0);
}

console.error("the extension's reach changed and extension/permissions.json does not say so\n");
console.error(`pinned:\n${want}\n`);
console.error(`manifest:\n${got}\n`);
console.error(
  "If this is deliberate: run `node extension/check-permissions.mjs --write`, then say in\n" +
    "`_comment` why the new entry is needed and how narrow it is. A widening nobody can\n" +
    "explain in a sentence is the one worth refusing.",
);
process.exit(1);
