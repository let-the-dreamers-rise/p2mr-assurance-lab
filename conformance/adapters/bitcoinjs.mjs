// bitcoinjs-lib adapter for the P2MR conformance pack.
// Built from implementations/bitcoinjs-lib/run.mjs, which produced the 2026-10-02
// results; this adapter itself has not yet been run against the pack.
//   BJS=/path/to/built/bitcoinjs-lib python conformance/check.py \
//       --adapter "node conformance/adapters/bitcoinjs.mjs"
const BJS = process.env.BJS;
if (!BJS) { console.error('set BJS=/path/to/bitcoinjs-lib checkout (built)'); process.exit(2); }
const { payments } = await import(BJS + '/src/esm/index.js');
const h = (x) => Buffer.from(x, 'hex');
const hx = (u) => Buffer.from(u).toString('hex');
const conv = (n) => Array.isArray(n)
  ? n.map(conv)
  : { output: h(n.script), version: n.leafVersion ?? 0xc0 };
const leaves = (n, acc = []) => { if (Array.isArray(n)) n.forEach((c) => leaves(c, acc)); else acc.push(n); return acc; };

let input = '';
for await (const chunk of process.stdin) input += chunk;
const out = [];
for (const c of JSON.parse(input)) {
  try {
    if (c.spend) {
      const output = Buffer.concat([Buffer.from([0x52, 0x20]), h(c.spend.program)]);
      payments.p2mr({ output, witness: [h(c.spend.script), h(c.spend.control)] });
      out.push({ id: c.id, valid: true });
      continue;
    }
    if (!c.script_tree) throw new Error('empty script tree');
    const tree = conv(c.script_tree);
    const p = payments.p2mr({ scriptTree: tree });
    const control_blocks = leaves(c.script_tree).map((l) => {
      const q = payments.p2mr({ scriptTree: tree,
        redeem: { output: h(l.script), redeemVersion: l.leafVersion ?? 0xc0 } });
      return hx(q.witness[q.witness.length - 1]);
    });
    out.push({ id: c.id, script_pubkey: hx(p.output), address: p.address, control_blocks });
  } catch (e) {
    out.push({ id: c.id, error: String(e.message) });
  }
}
process.stdout.write(JSON.stringify(out));
