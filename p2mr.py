"""Independent construction and validation primitives for BIP 360 (Pay-to-Merkle-Root).

Zero dependencies. Python 3.10+. Implemented from the BIP 360 specification text
(pinned revision recorded in vectors/MANIFEST.json), reusing the BIP 341 tree
machinery it references: TapLeaf/TapBranch tagged hashes, lexicographically sorted
branch pairs, compact_size script serialization, SegWit v2 outputs, and BIP 350
bech32m addresses. The taproot tweak (secp256k1) is implemented ONLY to verify the
specification's misuse vector -- P2MR itself must never apply it.

This is an independent test implementation for conformance checking. It is not a
wallet, does not handle secret material, and must not be used to construct mainnet
outputs: BIP 360 is a Draft and is not activated on Bitcoin mainnet.
"""

import hashlib


class P2MRError(ValueError):
    """Raised when construction or validation must fail per the specification."""


# ---------------------------------------------------------------------------
# Hashing (BIP 340 tagged hashes, as required by BIP 341 and reused by BIP 360)
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP 340: sha256(sha256(tag) || sha256(tag) || msg)."""
    t = sha256(tag.encode())
    return sha256(t + t + msg)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def compact_size(n: int) -> bytes:
    """Bitcoin CompactSize unsigned integer."""
    if n < 0:
        raise P2MRError("compact_size requires a non-negative integer")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def ser_script(script: bytes) -> bytes:
    """BIP 341 ser_script: compact_size(len(script)) || script."""
    return compact_size(len(script)) + script


# ---------------------------------------------------------------------------
# Script tree (BIP 341 machinery, key path removed per BIP 360)
# ---------------------------------------------------------------------------

DEFAULT_LEAF_VERSION = 0xC0
MAX_MERKLE_DEPTH = 128  # BIP 360: control block m is an integer in [0, 128]


def leaf_hash(leaf_version: int, script: bytes) -> bytes:
    """tagged_hash("TapLeaf", bytes([leaf_version]) || ser_script(script)).

    BIP 341 leaf versions are even (the low bit is reserved: in a control block
    it carries the parity flag, which BIP 360 requires to be 1).
    """
    if not 0 <= leaf_version <= 0xFE:
        raise P2MRError("leaf version out of range")
    if leaf_version & 1:
        raise P2MRError("leaf version must have its low bit clear (even value)")
    return tagged_hash("TapLeaf", bytes([leaf_version]) + ser_script(script))


def branch_hash(a: bytes, b: bytes) -> bytes:
    """tagged_hash("TapBranch", sorted pair) -- lexicographic order per BIP 341."""
    return tagged_hash("TapBranch", a + b if a < b else b + a)


def parse_script_tree(node):
    """Parse a fixture-format script tree.

    A node is either a leaf object (dict with "script" hex and optional
    "leafVersion") or a two-element list of nodes. Returns (root_hash, leaves)
    where leaves is a depth-first list of dicts:
        {"node": <leaf dict>, "hash": <leaf hash>, "path": [sibling hashes bottom-up]}
    """
    if node is None or node == "" or node == []:
        raise P2MRError("P2MR requires a script tree with at least one leaf")
    if isinstance(node, dict):
        version = node.get("leafVersion", DEFAULT_LEAF_VERSION)
        script = bytes.fromhex(node["script"])
        h = leaf_hash(version, script)
        return h, [{"node": node, "hash": h, "path": []}]
    if isinstance(node, list):
        if len(node) != 2:
            raise P2MRError("a script tree branch must have exactly two children")
        left_hash, left_leaves = parse_script_tree(node[0])
        right_hash, right_leaves = parse_script_tree(node[1])
        for leaf in left_leaves:
            leaf["path"].append(right_hash)
        for leaf in right_leaves:
            leaf["path"].append(left_hash)
        return branch_hash(left_hash, right_hash), left_leaves + right_leaves
    raise P2MRError("invalid script tree node type")


def construct_p2mr(script_tree, internal_pubkey=None):
    """Construct a P2MR output from a script tree.

    Returns dict with: merkle_root, leaf_hashes (DFS order), script_pubkey,
    address (mainnet bech32m), control_blocks (DFS order).

    Raises P2MRError on any misuse the specification defines as invalid.
    """
    if internal_pubkey:
        raise P2MRError("P2MR does not support internal pubkeys")
    root, leaves = parse_script_tree(script_tree)
    for leaf in leaves:
        if len(leaf["path"]) > MAX_MERKLE_DEPTH:
            raise P2MRError("merkle path depth exceeds 128")
    control_blocks = []
    for leaf in leaves:
        version = leaf["node"].get("leafVersion", DEFAULT_LEAF_VERSION)
        # BIP 360: the control byte's parity bit is always 1 (no key path spend).
        control = bytes([version | 1]) + b"".join(leaf["path"])
        control_blocks.append(control)
    return {
        "merkle_root": root,
        "leaf_hashes": [leaf["hash"] for leaf in leaves],
        "script_pubkey": make_script_pubkey(root),
        "address": bech32m_encode("bc", 2, root),
        "control_blocks": control_blocks,
    }


# ---------------------------------------------------------------------------
# scriptPubKey
# ---------------------------------------------------------------------------

OP_2 = 0x52
OP_PUSHBYTES_32 = 0x20


def make_script_pubkey(merkle_root: bytes) -> bytes:
    """OP_2 OP_PUSHBYTES_32 <32-byte merkle root> (BIP 360 ScriptPubKey)."""
    if len(merkle_root) != 32:
        raise P2MRError("P2MR witness program must be exactly 32 bytes")
    return bytes([OP_2, OP_PUSHBYTES_32]) + merkle_root


def parse_script_pubkey(script_pubkey: bytes) -> bytes:
    """Return the 32-byte witness program of a P2MR scriptPubKey, or raise."""
    if len(script_pubkey) != 34:
        raise P2MRError("P2MR scriptPubKey must be exactly 34 bytes")
    if script_pubkey[0] != OP_2:
        raise P2MRError("not a SegWit version 2 output")
    if script_pubkey[1] != OP_PUSHBYTES_32:
        raise P2MRError("witness program push must be 32 bytes")
    return script_pubkey[2:]


# ---------------------------------------------------------------------------
# Script-path validation walk (BIP 360, Script Validation)
# ---------------------------------------------------------------------------

def validate_script_path(program_q: bytes, script: bytes, control: bytes) -> bool:
    """Recompute the merkle root from (script, control block) and compare to q.

    Implements the BIP 360 validation walk:
      - control block length must be 1 + 32*m for m in [0, 128]
      - the control byte's low bit must be 1; v = c[0] & 0xfe
      - k0 = TapLeaf(v || compact_size(|s|) || s)
      - k_{j+1} = TapBranch(sorted(k_j, e_j))
      - fail if q != k_m
    """
    if len(program_q) != 32:
        raise P2MRError("witness program must be 32 bytes")
    if len(control) < 1 or (len(control) - 1) % 32 != 0:
        raise P2MRError("control block length must be 1 + 32*m")
    m = (len(control) - 1) // 32
    if m > MAX_MERKLE_DEPTH:
        raise P2MRError("control block depth m exceeds 128")
    if control[0] & 1 != 1:
        raise P2MRError("control byte parity bit must be 1")
    version = control[0] & 0xFE
    k = tagged_hash("TapLeaf", bytes([version]) + ser_script(script))
    for j in range(m):
        e = control[1 + 32 * j: 33 + 32 * j]
        k = branch_hash(k, e)
    if k != program_q:
        raise P2MRError("computed merkle root does not match witness program")
    return True


# ---------------------------------------------------------------------------
# Bech32m (BIP 350) -- reference algorithm, implemented independently
# ---------------------------------------------------------------------------

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_create_checksum(hrp, data, const):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise P2MRError("invalid value in bit conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise P2MRError("invalid padding in bit conversion")
    return ret


def bech32m_encode(hrp: str, witver: int, program: bytes, const: int = BECH32M_CONST) -> str:
    """Encode a SegWit address. Witness versions 1+ use the bech32m constant."""
    if witver < 1 or witver > 16:
        raise P2MRError("bech32m encoding is for witness versions 1 through 16")
    data = [witver] + _convertbits(program, 8, 5)
    checksum = _bech32_create_checksum(hrp, data, const)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def bech32m_decode(addr: str):
    """Decode a bech32m SegWit address; returns (hrp, witver, program bytes).

    Raises P2MRError on bad charset, bad checksum, wrong checksum constant for
    witness versions 1+, or invalid program length.
    """
    if addr != addr.lower() and addr != addr.upper():
        raise P2MRError("mixed-case address")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        raise P2MRError("invalid address framing")
    hrp, data_part = addr[:pos], addr[pos + 1:]
    if any(c not in BECH32_CHARSET for c in data_part):
        raise P2MRError("invalid character in address")
    data = [BECH32_CHARSET.find(c) for c in data_part]
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != BECH32M_CONST:
        raise P2MRError("bech32m checksum failed")
    witver = data[0]
    if witver < 1:
        raise P2MRError("bech32m is only valid for witness versions 1 through 16")
    program = bytes(_convertbits(data[1:-6], 5, 8, pad=False))
    if len(program) < 2 or len(program) > 40:
        raise P2MRError("invalid witness program length")
    return hrp, witver, program


# ---------------------------------------------------------------------------
# secp256k1 taproot tweak -- ONLY to verify the specification's misuse vector.
# P2MR must never apply this; the fixture documents what a faulty P2TR-style
# construction would produce so implementations can test their refusal path.
# ---------------------------------------------------------------------------

_FIELD_P = 2 ** 256 - 2 ** 32 - 977
_CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _FIELD_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, _FIELD_P - 2, _FIELD_P) % _FIELD_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _FIELD_P - 2, _FIELD_P) % _FIELD_P
    x3 = (lam * lam - x1 - x2) % _FIELD_P
    return x3, (lam * (x1 - x3) - y1) % _FIELD_P


def _point_mul(point, scalar):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _lift_x(x: int):
    if x >= _FIELD_P:
        return None
    y_sq = (pow(x, 3, _FIELD_P) + 7) % _FIELD_P
    y = pow(y_sq, (_FIELD_P + 1) // 4, _FIELD_P)
    if pow(y, 2, _FIELD_P) != y_sq:
        return None
    return x, y if y % 2 == 0 else _FIELD_P - y


def taproot_tweak(internal_pubkey: bytes, merkle_root: bytes = b""):
    """BIP 341 output-key tweak. Returns (tweak bytes, tweaked x-only pubkey).

    Exists solely to verify the misuse vector: P2MR outputs must NOT be built
    this way, and construct_p2mr refuses any internal pubkey.
    """
    t = int.from_bytes(tagged_hash("TapTweak", internal_pubkey + merkle_root), "big")
    if t >= _CURVE_N:
        raise P2MRError("tweak overflows curve order")
    point = _lift_x(int.from_bytes(internal_pubkey, "big"))
    if point is None:
        raise P2MRError("internal pubkey is not on the curve")
    q = _point_add(point, _point_mul(_G, t))
    return t.to_bytes(32, "big"), q[0].to_bytes(32, "big")
