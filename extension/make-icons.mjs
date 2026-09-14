// Draw the extension's icons.
//
// A script rather than four checked-in blobs nobody can edit. The mark is a shell prompt — a
// chevron and a cursor bar — because at sixteen pixels one idea is all that survives, and
// "this is a terminal" is the idea worth keeping. Change the numbers below and re-run.
//
//   npm --prefix extension run icons
//
// Each PNG is written by hand from `zlib` and a CRC table, so this needs nothing installed.
// The alternative was taking on a dependency in order to draw two rectangles.
//
// Nothing here varies with the clock, so re-running produces byte-identical files. An icon
// that changed every time it was regenerated would put noise in every diff that touched it.

import { deflateSync } from "node:zlib";

import { crc32 } from "./crc32.mjs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, "icons");

/// The four Chrome asks for: 16 in the toolbar, 48 on the extensions page, 128 in the store,
/// and 32 for the displays that sit between them.
///
/// The 128 is drawn smaller inside its square, and that is the store's rule rather than a
/// preference: the listing wants 96×96 of artwork with 16 transparent pixels on every side,
/// because it draws its own rounded frame around whatever it is given and a tile that fills
/// the canvas has that frame drawn across its corners. The others are toolbar icons, where the
/// opposite holds and padding is wasted pixels at sixteen across.
///
/// Still one drawing. `fill` is where it is sampled from, not a second set of numbers.
const SIZES = [
  { px: 16, fill: 1 },
  { px: 32, fill: 1 },
  { px: 48, fill: 1 },
  // The tile is 93% of the canvas, so 96/128 of the canvas means 96/119 of the tile.
  { px: 128, fill: 96 / 119 },
];

/// Supersampling factor. Drawn straight at 16×16 the diagonals stair-step; drawn at 64×64 and
/// averaged down, the same shape has edges that read as smooth.
const SS = 4;

const BACKGROUND = [0x1f, 0x29, 0x33]; // slate, dark enough to carry a light mark
const INK = [0xff, 0xfd, 0xf5]; // the annotation panel's off-white, so the two look related

/// Signed distance to a rounded rectangle, negative inside.
function roundedRect(x, y, w, h, r) {
  const dx = Math.abs(x) - (w / 2 - r);
  const dy = Math.abs(y) - (h / 2 - r);
  const outside = Math.hypot(Math.max(dx, 0), Math.max(dy, 0));
  return outside + Math.min(Math.max(dx, dy), 0) - r;
}

/// Signed distance to a thick line segment, negative inside.
function segment(x, y, ax, ay, bx, by, half) {
  const vx = bx - ax;
  const vy = by - ay;
  const t = Math.max(0, Math.min(1, ((x - ax) * vx + (y - ay) * vy) / (vx * vx + vy * vy)));
  return Math.hypot(x - (ax + t * vx), y - (ay + t * vy)) - half;
}

/// The mark, in a coordinate system running -1..1 on both axes.
///
/// Defined once and sampled at every size, so the four icons are one drawing rather than four
/// drawings that happen to resemble each other.
function ink(x, y) {
  const stroke = 0.13;
  // The chevron: two strokes meeting at the right.
  const upper = segment(x, y, -0.55, -0.38, -0.1, 0.0, stroke);
  const lower = segment(x, y, -0.55, 0.38, -0.1, 0.0, stroke);
  // The cursor, on the baseline to the right of it.
  const bar = segment(x, y, 0.16, 0.36, 0.58, 0.36, stroke);
  return Math.min(upper, lower, bar);
}

function render(size, fill) {
  const n = size * SS;
  const px = new Uint8Array(size * size * 4);

  for (let py = 0; py < size; py += 1) {
    for (let pxi = 0; pxi < size; pxi += 1) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;

      for (let sy = 0; sy < SS; sy += 1) {
        for (let sx = 0; sx < SS; sx += 1) {
          // The centre of each subpixel, mapped to -1..1.
          // Divided by `fill`, so a smaller `fill` moves the sample further out and the
          // drawing lands smaller in the same square. One drawing, sampled from further away.
          const u = (((pxi * SS + sx + 0.5) / n) * 2 - 1) / fill;
          const v = (((py * SS + sy + 0.5) / n) * 2 - 1) / fill;

          if (roundedRect(u, v, 1.86, 1.86, 0.42) > 0) {
            continue;
          }
          const [cr, cg, cb] = ink(u, v) <= 0 ? INK : BACKGROUND;
          r += cr;
          g += cg;
          b += cb;
          a += 255;
        }
      }

      // Averaged over every subpixel, the ones outside the rounded corners included — which
      // is what turns those corners into a smooth edge rather than a staircase.
      const taken = SS * SS;
      const i = (py * size + pxi) * 4;
      px[i] = Math.round(r / taken);
      px[i + 1] = Math.round(g / taken);
      px[i + 2] = Math.round(b / taken);
      px[i + 3] = Math.round(a / taken);
    }
  }
  return px;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

function png(size, pixels) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // colour type: RGBA
  // Compression, filter and interlace keep their only defined values.

  // One filter byte per scanline, always zero — "no filter". These images are tiny and flat,
  // so a filter would buy nothing and cost a reader of this file their understanding of it.
  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y += 1) {
    raw[y * (stride + 1)] = 0;
    Buffer.from(pixels.buffer, y * stride, stride).copy(raw, y * (stride + 1) + 1);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

await mkdir(OUT, { recursive: true });
for (const { px: size, fill } of SIZES) {
  await writeFile(join(OUT, `icon-${size}.png`), png(size, render(size, fill)));
  console.log(`  wrote icons/icon-${size}.png`);
}
