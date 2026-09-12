// CRC-32, the one both PNG and ZIP want.
//
// Shared so that the icon writer and the packager cannot drift into two slightly different
// tables — the kind of difference that produces a file every tool but one will open.
//
// CRC-32/ISO-HDLC: reflected, polynomial 0xedb88320, initial and final xor 0xffffffff. The
// standard check value is crc32("123456789") === 0xcbf43926.

const TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

export function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) {
    c = TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}
