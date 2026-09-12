// Zip dist/ into the file the Chrome Web Store wants uploaded.
//
//   npm --prefix extension run build && npm --prefix extension run package
//
// Written by hand rather than pulled from a package, for two reasons. This half ships to a
// store, and every dependency in its toolchain is one more thing a reviewer — or a reader —
// has to take on trust. And the format is a local header, a central directory and an
// end-of-central-directory record, which is less code than the wrapper around it would be.
//
// The output is reproducible: entries are sorted, timestamps are fixed and deflate is given a
// fixed level. Anyone can rebuild from the same commit and compare hashes against what was
// uploaded, which is worth having for an extension that holds a control token.

import { deflateRawSync } from "node:zlib";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { crc32 } from "./crc32.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const DIST = join(here, "dist");

/// 1980-01-01 00:00, the earliest a DOS timestamp can express.
///
/// Fixed rather than real: a zip whose bytes depend on when it was built cannot be compared
/// against a rebuild, and the modification time of a file inside an extension is of no
/// interest to anybody.
const DOS_DATE = (1 << 5) | 1; // year 1980, month 1, day 1
const DOS_TIME = 0;

async function filesUnder(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await filesUnder(full)));
    } else {
      out.push(full);
    }
  }
  return out;
}

function localHeader(name, entry) {
  const b = Buffer.alloc(30 + Buffer.byteLength(name));
  b.writeUInt32LE(0x04034b50, 0);
  b.writeUInt16LE(20, 4); // version needed
  b.writeUInt16LE(0, 6); // flags
  b.writeUInt16LE(8, 8); // deflate
  b.writeUInt16LE(DOS_TIME, 10);
  b.writeUInt16LE(DOS_DATE, 12);
  b.writeUInt32LE(entry.crc, 14);
  b.writeUInt32LE(entry.deflated.length, 18);
  b.writeUInt32LE(entry.size, 22);
  b.writeUInt16LE(Buffer.byteLength(name), 26);
  b.writeUInt16LE(0, 28); // no extra field
  b.write(name, 30, "utf8");
  return b;
}

function centralEntry(name, entry) {
  const b = Buffer.alloc(46 + Buffer.byteLength(name));
  b.writeUInt32LE(0x02014b50, 0);
  b.writeUInt16LE(20, 4); // version made by
  b.writeUInt16LE(20, 6); // version needed
  b.writeUInt16LE(0, 8); // flags
  b.writeUInt16LE(8, 10); // deflate
  b.writeUInt16LE(DOS_TIME, 12);
  b.writeUInt16LE(DOS_DATE, 14);
  b.writeUInt32LE(entry.crc, 16);
  b.writeUInt32LE(entry.deflated.length, 20);
  b.writeUInt32LE(entry.size, 24);
  b.writeUInt16LE(Buffer.byteLength(name), 28);
  // No extra field, no comment, disk zero, no attributes worth setting: a zip of static
  // assets has nothing to say in any of them, and every field left at zero is a field that
  // cannot vary between builds.
  b.writeUInt32LE(entry.offset, 42);
  b.write(name, 46, "utf8");
  return b;
}

const files = (await filesUnder(DIST)).sort();
if (files.length === 0) {
  throw new Error(`nothing in ${DIST} — run: npm --prefix extension run build`);
}

const manifest = JSON.parse(await readFile(join(DIST, "manifest.json"), "utf8"));
const zipName = `ssh-browser-${manifest.version}.zip`;

const parts = [];
const central = [];
let offset = 0;

for (const file of files) {
  // Zip paths are forward-slashed whatever the host separator is, and are relative to dist/
  // so the archive unpacks as the extension root rather than as a folder called dist.
  const name = relative(DIST, file).split(sep).join("/");
  const body = await readFile(file);
  const entry = {
    size: body.length,
    crc: crc32(body),
    deflated: deflateRawSync(body, { level: 9 }),
    offset,
  };

  const header = localHeader(name, entry);
  parts.push(header, entry.deflated);
  central.push(centralEntry(name, entry));
  offset += header.length + entry.deflated.length;
}

const directory = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(files.length, 8);
end.writeUInt16LE(files.length, 10);
end.writeUInt32LE(directory.length, 12);
end.writeUInt32LE(offset, 16);

const zip = Buffer.concat([...parts, directory, end]);
await writeFile(join(here, zipName), zip);

console.log(`  ${zipName}  ${files.length} files, ${zip.length} bytes`);
for (const file of files) {
  console.log(`    ${relative(DIST, file).split(sep).join("/")}`);
}
