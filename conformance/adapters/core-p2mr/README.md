# Bitcoin Core + CipherScope P2MR patches: adapter

Runs the conformance pack against Bitcoin Core v31.1 with CipherScope's BIP 360
patch series ([duncan0k/bitcoin-p2mr-patches](https://github.com/duncan0k/bitcoin-p2mr-patches):
the M0 consensus series plus the M0.5 wallet series, which the Ark-0 signet runs).

- **Building outputs**: the patched `TaprootBuilder` (`GetP2MROutput`,
  `GetP2MRSpendData`), the same path the series' `tmr()` descriptor uses. Depth and
  tree shape are checked by Core's `TaprootBuilder::ValidDepths`.
- **Validating spends**: the patched consensus `VerifyScript` with `SCRIPT_VERIFY_P2MR`.
- **Addresses**: Core's bech32m encoder with the `bc` prefix.

Checked by the adapter rather than by Core (the report says so): an empty tree and an
odd leaf version (`TaprootBuilder::Add` asserts on those instead of returning an
error), and a branch without exactly two children (the pack's nested tree is
flattened to Core's depth list by the adapter).

## Build and run (Linux)

```sh
git clone https://github.com/duncan0k/bitcoin-p2mr-patches
git clone --branch v31.1 --depth 1 https://github.com/bitcoin/bitcoin.git core-p2mr && cd core-p2mr
git checkout -B p2mr
git am ../bitcoin-p2mr-patches/patches/*.patch ../bitcoin-p2mr-patches/patches-m05/*.patch
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DENABLE_WALLET=OFF -DBUILD_GUI=OFF \
  -DWITH_ZMQ=OFF -DENABLE_IPC=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DBUILD_DAEMON=OFF \
  -DBUILD_CLI=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DBUILD_WALLET_TOOL=OFF
cmake --build build -j4 --target bitcoin_common bitcoin_consensus bitcoin_crypto bitcoin_util \
  bitcoin_clientversion secp256k1 univalue
g++ -std=c++20 -O1 -I src -I build/src -I src/univalue/include -I src/secp256k1/include \
  /path/to/p2mr-assurance-lab/conformance/adapters/core-p2mr/core_p2mr_adapter.cpp -o core_adapter \
  build/lib/libbitcoin_common.a build/lib/libbitcoin_consensus.a build/lib/libbitcoin_util.a \
  build/lib/libbitcoin_clientversion.a build/lib/libbitcoin_crypto.a \
  build/src/univalue/libunivalue.a build/src/secp256k1/lib/libsecp256k1.a -lpthread
python3 /path/to/p2mr-assurance-lab/conformance/check.py --adapter ./core_adapter
```
