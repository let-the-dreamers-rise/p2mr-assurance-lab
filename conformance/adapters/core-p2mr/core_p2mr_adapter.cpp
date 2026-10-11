// Adapter for Bitcoin Core v31.1 with CipherScope's BIP 360 patch series
// (github.com/duncan0k/bitcoin-p2mr-patches, M0 consensus + M0.5 wallet series).
//
// Builds outputs with the patched TaprootBuilder (GetP2MROutput / GetP2MRSpendData,
// the path the tmr() descriptor uses), checks depths with TaprootBuilder::ValidDepths,
// and validates spends with the patched consensus VerifyScript (SCRIPT_VERIFY_P2MR).
// Build: see README.md in this directory.
#include <addresstype.h>
#include <bech32.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <functional>
#include <iostream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

// Required by Bitcoin Core's util library; standalone tools set it to nullptr.
const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

struct Leaf {
    int depth;
    std::vector<unsigned char> script;
    int leaf_version;
};

// The pack uses BIP 360's nested JSON tree; TaprootBuilder takes leaves in DFS order with
// their depths, so the nesting is flattened here. Shape errors (an empty tree or a
// branch without exactly two children) are therefore caught by this adapter, and the
// report says so.
void Flatten(const UniValue& node, int depth, std::vector<Leaf>& out)
{
    if (node.isArray()) {
        if (node.size() != 2) throw std::runtime_error("adapter: a branch must have exactly two children");
        Flatten(node[0], depth + 1, out);
        Flatten(node[1], depth + 1, out);
        return;
    }
    if (!node.isObject()) throw std::runtime_error("adapter: invalid tree node");
    int version = node.exists("leafVersion") ? node["leafVersion"].getInt<int>() : 0xc0;
    out.push_back({depth, ParseHex(node["script"].get_str()), version});
}

// TaprootBuilder::Add asserts an even leaf version and the builder needs a non-empty
// tree, so those two are checked here (adapter-side, and the report says so). Depth
// and tree shape are checked by Core's own TaprootBuilder::ValidDepths.
TaprootBuilder BuildChecked(const std::vector<Leaf>& leaves)
{
    if (leaves.empty()) throw std::runtime_error("adapter: tree must contain at least one leaf");
    std::vector<int> depths;
    for (const auto& leaf : leaves) {
        if ((leaf.leaf_version & ~TAPROOT_LEAF_MASK) != 0) throw std::runtime_error("adapter: leaf version must be even");
        depths.push_back(leaf.depth);
    }
    if (!TaprootBuilder::ValidDepths(depths)) throw std::runtime_error("TaprootBuilder::ValidDepths rejected the tree");
    TaprootBuilder builder;
    for (const auto& leaf : leaves) builder.Add(leaf.depth, leaf.script, leaf.leaf_version);
    if (!builder.IsValid() || !builder.IsComplete()) throw std::runtime_error("TaprootBuilder: incomplete tree");
    return builder;
}

std::string MainnetAddress(const WitnessV2P2MR& out)
{
    // Core's own bech32m encoder with mainnet's "bc" prefix (the patches never activate
    // P2MR on mainnet; the address encoding is the same on every network but the prefix).
    std::vector<unsigned char> data = {2};
    ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, out.begin(), out.end());
    return bech32::Encode(bech32::Encoding::BECH32M, "bc", data);
}

UniValue Construct(const UniValue& c)
{
    const UniValue& tree = c["script_tree"];
    std::vector<Leaf> leaves;
    if (!(tree.isNull() || (tree.isStr() && tree.get_str().empty()))) Flatten(tree, 0, leaves);
    TaprootBuilder builder = BuildChecked(leaves);
    WitnessV2P2MR output = builder.GetP2MROutput();
    CScript spk = GetScriptForDestination(output);
    P2MRSpendData spend = builder.GetP2MRSpendData();

    UniValue r(UniValue::VOBJ);
    r.pushKV("id", c["id"]);
    r.pushKV("script_pubkey", HexStr(spk));
    r.pushKV("address", MainnetAddress(output));
    UniValue cbs(UniValue::VARR);
    // GetP2MRSpendData keeps every control block per (script, leaf version), shortest
    // first. Report them per leaf in DFS order; identical leaves take successive
    // entries of the same set.
    std::map<std::pair<std::vector<unsigned char>, int>, size_t> used;
    for (const auto& leaf : leaves) {
        const auto key = std::make_pair(leaf.script, leaf.leaf_version);
        const auto& set = spend.scripts.at(key);
        auto it = set.begin();
        std::advance(it, std::min(used[key]++, set.size() - 1));
        cbs.push_back(HexStr(*it));
    }
    r.pushKV("control_blocks", cbs);
    return r;
}

UniValue Spend(const UniValue& c)
{
    const UniValue& sp = c["spend"];
    std::vector<unsigned char> program = ParseHex(sp["program"].get_str());
    CScript spk;
    spk << OP_2 << program;
    CScriptWitness witness;
    witness.stack.push_back(ParseHex(sp["script"].get_str()));
    witness.stack.push_back(ParseHex(sp["control"].get_str()));
    const script_verify_flags flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT | SCRIPT_VERIFY_P2MR;
    ScriptError err;
    BaseSignatureChecker checker;
    UniValue r(UniValue::VOBJ);
    r.pushKV("id", c["id"]);
    if (VerifyScript(CScript(), spk, &witness, flags, checker, &err)) {
        r.pushKV("valid", true);
    } else {
        r.pushKV("error", ScriptErrorString(err));
    }
    return r;
}

} // namespace

int main()
{
    std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
    UniValue cases;
    if (!cases.read(input) || !cases.isArray()) {
        std::cerr << "expected a JSON array on stdin\n";
        return 2;
    }
    UniValue out(UniValue::VARR);
    for (size_t i = 0; i < cases.size(); ++i) {
        const UniValue& c = cases[i];
        try {
            out.push_back(c.exists("spend") ? Spend(c) : Construct(c));
        } catch (const std::exception& e) {
            UniValue r(UniValue::VOBJ);
            r.pushKV("id", c["id"]);
            r.pushKV("error", e.what());
            out.push_back(r);
        }
    }
    std::cout << out.write() << std::endl;
    return 0;
}
