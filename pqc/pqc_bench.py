"""Post-quantum signature cost benchmark for Bitcoin P2MR spends.

Usage: python pqc/pqc_bench.py

BIP 360's stated purpose is to give tapscript a quantum-resistant home so that
post-quantum signature opcodes can be introduced later. The obvious unanswered
question is: what would that actually cost on-chain? This computes it from
first principles, using only published constants:

  - NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA) public-key and signature sizes
    (fixed, standardized values -- see pqc/PARAMS.md for the citation table)
  - Bitcoin's BIP 141 witness-discount weight model (witness byte = 1 weight
    unit = 0.25 vbytes; non-witness byte = 4 weight units = 1 vbyte)
  - a standard 4,000,000 weight-unit (~1,000,000 vbyte) block

Everything here is size/fee/capacity arithmetic that is exactly reproducible.
Signature *verification CPU time* is deliberately NOT reported: it cannot be
measured honestly without a pinned liboqs build, and is scoped as funded work
(see the proposal). Fabricated timings would defeat the purpose of the lab.
"""

# ---------------------------------------------------------------------------
# Published NIST parameter sizes (bytes). Sources in pqc/PARAMS.md.
# ---------------------------------------------------------------------------

# FIPS 204 -- ML-DSA (lattice, Dilithium)
ML_DSA = {
    "ML-DSA-44": {"pubkey": 1312, "sig": 2420, "nist_level": 2},
    "ML-DSA-65": {"pubkey": 1952, "sig": 3309, "nist_level": 3},
    "ML-DSA-87": {"pubkey": 2592, "sig": 4627, "nist_level": 5},
}

# FIPS 205 -- SLH-DSA (hash-based, SPHINCS+). 's' = small sig, 'f' = fast.
SLH_DSA = {
    "SLH-DSA-128s": {"pubkey": 32, "sig": 7856, "nist_level": 1},
    "SLH-DSA-128f": {"pubkey": 32, "sig": 17088, "nist_level": 1},
    "SLH-DSA-192s": {"pubkey": 48, "sig": 16224, "nist_level": 3},
    "SLH-DSA-256s": {"pubkey": 64, "sig": 29792, "nist_level": 5},
}

# Current Bitcoin baseline: BIP 340 Schnorr over secp256k1.
SCHNORR = {"pubkey": 32, "sig": 64, "nist_level": 0}

# ---------------------------------------------------------------------------
# Bitcoin serialization / weight model (BIP 141)
# ---------------------------------------------------------------------------

WITNESS_WEIGHT_PER_BYTE = 1
NONWITNESS_WEIGHT_PER_BYTE = 4
BLOCK_WEIGHT = 4_000_000


def compact_size_len(n: int) -> int:
    """Byte length of a CompactSize prefix for a value n."""
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def push_len(data_len: int) -> int:
    """Bytes to push `data_len` bytes in Bitcoin script (opcode + optional length)."""
    if data_len < 0x4C:
        return 1 + data_len            # direct push opcode
    if data_len <= 0xFF:
        return 2 + data_len            # OP_PUSHDATA1
    if data_len <= 0xFFFF:
        return 3 + data_len            # OP_PUSHDATA2
    return 5 + data_len                # OP_PUSHDATA4


def witness_item_len(data_len: int) -> int:
    """A witness stack item is CompactSize(len) || data."""
    return compact_size_len(data_len) + data_len


def p2mr_input_cost(sig_bytes: int, pubkey_bytes: int, merkle_depth: int = 1):
    """Weight and vbytes of ONE P2MR script-path input spending a single-sig leaf.

    Witness stack: [signature] [leaf script] [control block], plus the stack
    item-count byte. Leaf script = <push pubkey> + 1 checksig-style opcode.
    Control block = 1 + 32*depth. Non-witness input part = outpoint(36) +
    empty scriptSig(1) + sequence(4).
    """
    leaf_script_len = push_len(pubkey_bytes) + 1
    control_block_len = 1 + 32 * merkle_depth

    witness_bytes = (
        1  # witness stack item count
        + witness_item_len(sig_bytes)
        + witness_item_len(leaf_script_len)
        + witness_item_len(control_block_len)
    )
    nonwitness_bytes = 36 + 1 + 4

    weight = witness_bytes * WITNESS_WEIGHT_PER_BYTE + nonwitness_bytes * NONWITNESS_WEIGHT_PER_BYTE
    vbytes = weight / 4.0
    return {
        "witness_bytes": witness_bytes,
        "nonwitness_bytes": nonwitness_bytes,
        "weight": weight,
        "vbytes": vbytes,
        "inputs_per_block": BLOCK_WEIGHT // weight,
    }


def schnorr_keypath_cost():
    """Baseline: a P2TR key-path spend is just a 64/65-byte Schnorr signature."""
    witness_bytes = 1 + witness_item_len(64)
    nonwitness_bytes = 36 + 1 + 4
    weight = witness_bytes + nonwitness_bytes * 4
    return {"weight": weight, "vbytes": weight / 4.0, "inputs_per_block": BLOCK_WEIGHT // weight}


def fee_usd(vbytes: float, sat_per_vb: float, btc_usd: float) -> float:
    return vbytes * sat_per_vb / 1e8 * btc_usd


def fmt(n):
    return f"{n:,}"


def main():
    # Illustrative market parameters (clearly labeled; the model is what matters).
    fee_rates = [5, 20, 50]          # sat/vB
    btc_usd = 100_000                # round figure for legibility

    base = schnorr_keypath_cost()
    print("=" * 78)
    print("Post-quantum signature cost for a single P2MR input (depth-1 leaf)")
    print("Model: BIP 141 witness discount; block = 4,000,000 WU (~1,000,000 vB)")
    print(f"Illustrative: BTC = ${fmt(btc_usd)}; fee rates {fee_rates} sat/vB")
    print("=" * 78)
    print(f"\nBaseline  BIP 340 Schnorr P2TR key-path spend:")
    print(f"  {base['vbytes']:.1f} vB/input  ·  {fmt(int(base['inputs_per_block']))} inputs/block")

    header = f"\n{'scheme':<14}{'NIST':>5}{'pk B':>7}{'sig B':>8}{'vB/in':>9}{'x vs Schnorr':>13}{'inputs/blk':>12}"
    rows = []
    for name, p in list(ML_DSA.items()) + list(SLH_DSA.items()):
        c = p2mr_input_cost(p["sig"], p["pubkey"])
        rows.append((name, p, c))

    print(header)
    print("-" * len(header.strip()))
    for name, p, c in rows:
        ratio = c["vbytes"] / base["vbytes"]
        print(f"{name:<14}{p['nist_level']:>5}{fmt(p['pubkey']):>7}{fmt(p['sig']):>8}"
              f"{c['vbytes']:>9.1f}{ratio:>12.0f}x{fmt(int(c['inputs_per_block'])):>12}")

    print(f"\nFee per single PQC input at BTC = ${fmt(btc_usd)}:")
    fh = f"{'scheme':<14}" + "".join(f"{str(r)+' sat/vB':>14}" for r in fee_rates)
    print(fh)
    print("-" * len(fh))
    for name, p, c in rows:
        line = f"{name:<14}"
        for r in fee_rates:
            line += f"{'$' + format(fee_usd(c['vbytes'], r, btc_usd), ',.2f'):>14}"
        print(line)

    print("\nKey observations (exact, reproducible):")
    mldsa44 = p2mr_input_cost(ML_DSA['ML-DSA-44']['sig'], ML_DSA['ML-DSA-44']['pubkey'])
    slh256s = p2mr_input_cost(SLH_DSA['SLH-DSA-256s']['sig'], SLH_DSA['SLH-DSA-256s']['pubkey'])
    print(f"  - The smallest PQC option (ML-DSA-44) is ~{mldsa44['vbytes']/base['vbytes']:.0f}x a Schnorr"
          f" spend and cuts block input capacity from {fmt(int(base['inputs_per_block']))} to"
          f" {fmt(int(mldsa44['inputs_per_block']))}.")
    print(f"  - A conservative hash-based choice (SLH-DSA-256s) reaches"
          f" {slh256s['vbytes']:.0f} vB/input: only {fmt(int(slh256s['inputs_per_block']))}"
          f" such inputs fit in a block.")
    print("  - Verification CPU time is NOT reported here: it requires a pinned liboqs")
    print("    build and is scoped as funded work. This benchmark reports only what")
    print("    published constants determine exactly.")


if __name__ == "__main__":
    main()
