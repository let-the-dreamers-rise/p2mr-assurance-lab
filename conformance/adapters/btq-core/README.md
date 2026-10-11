# btq-core adapter

Runs the conformance pack against [btq-ag/btq-core](https://github.com/btq-ag/btq-core)'s
own P2MR code:

- **Building outputs**: btq-core's `P2MRBuilder` (`src/script/signingprovider.cpp`),
  with the same input checks, in the same order, as btq-core's wallet entry point
  `BuildP2MRTreeChecked` (`src/wallet/p2mr.cpp`). Those checks are copied into the
  adapter because the wallet library is not linked.
- **Validating spends**: btq-core's consensus `VerifyScript` with
  `SCRIPT_VERIFY_P2MR` (the witness v2 branch of `src/script/interpreter.cpp`).
- **Addresses**: btq-core's bech32m encoder with Bitcoin's `bc` prefix, so results
  compare against the pack. BTQ's own networks use `qbtc`, `tbtq` and `qtb`.

The pack's nested tree is flattened to btq-core's depth-first `(depth, leaf)` list
by the adapter, so the `three_child_branch_rejected` case is decided by the
adapter, not by btq-core. For identical leaves, `GetSpendData` keeps every control
block shortest-first; the adapter hands them out in depth-first order.

## Build and run (Linux)

```sh
git clone https://github.com/btq-ag/btq-core && cd btq-core
./autogen.sh
./configure --disable-wallet --without-gui --disable-bench --disable-tests \
  --disable-fuzz-binary --with-utils=no --with-daemon=no --with-libs=yes
cd src
make -j4 libbtq_common.a libbtq_consensus.a libbtq_util.a libunivalue.la \
  crypto/libbtq_crypto_base.la crypto/libbtq_crypto_sse41.la \
  crypto/libbtq_crypto_avx2.la crypto/libbtq_crypto_x86_shani.la secp256k1/libsecp256k1.la
g++ -std=c++17 -O1 -DHAVE_CONFIG_H -I. -Iconfig -Iunivalue/include -Isecp256k1/include \
  /path/to/p2mr-assurance-lab/conformance/adapters/btq-core/btq_adapter.cpp -o btq_adapter \
  libbtq_common.a libbtq_consensus.a libbtq_util.a .libs/libunivalue.a \
  crypto/.libs/libbtq_crypto_base.a crypto/.libs/libbtq_crypto_sse41.a \
  crypto/.libs/libbtq_crypto_avx2.a crypto/.libs/libbtq_crypto_x86_shani.a \
  secp256k1/.libs/libsecp256k1.a secp256k1/.libs/libsecp256k1_precomputed.a -lpthread
python3 /path/to/p2mr-assurance-lab/conformance/check.py --adapter ./btq_adapter
```
