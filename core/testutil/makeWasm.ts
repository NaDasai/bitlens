/**
 * Tiny hand-rolled WASM encoder for tests: a module whose functions all have
 * type () -> (), importing the given `env` host functions and exporting the
 * given method names. Enough to exercise the parser + import scanner offline.
 */
function leb(n: number): number[] {
  const out: number[] = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n) b |= 0x80;
    out.push(b);
  } while (n);
  return out;
}
const str = (s: string) => [...leb(Buffer.byteLength(s)), ...Buffer.from(s)];
const vec = (items: number[][]) => [...leb(items.length), ...items.flat()];
const section = (id: number, body: number[]) => [id, ...leb(body.length), ...body];

export function makeWasm(imports: string[], exports: string[]): Uint8Array {
  const type = section(1, vec([[0x60, 0x00, 0x00]]));
  const imp = section(2, vec(imports.map((n) => [...str("env"), ...str(n), 0x00, 0x00])));
  const funcs = section(3, vec(exports.map(() => [0x00])));
  const exp = section(7, vec(exports.map((n, i) => [...str(n), 0x00, ...leb(imports.length + i)])));
  const code = section(10, vec(exports.map(() => [0x02, 0x00, 0x0b])));
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...type, ...imp, ...funcs, ...exp, ...code]);
}
