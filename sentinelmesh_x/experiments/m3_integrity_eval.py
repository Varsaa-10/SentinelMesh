"""M3: cryptographic integrity detection per attack class, false-positive rate, latency. Separate from semantic poisoning (shown explicitly)."""
import base64, copy, random, tempfile, time, unicodedata
from m1_common import *
from sentinelmesh_x.integrity import *
OUT3 = ROOT / "results_x_v3"; OUT3.mkdir(exist_ok=True)
rng = random.Random(SEED); tmp = Path(tempfile.mkdtemp())          # keys live OUTSIDE the repo and are not packaged
priv, pub = generate_dev_keypair(tmp / "keys"); sk, pk = load_private(priv), load_public(pub)
_, pub2 = generate_dev_keypair(tmp / "keys2", "other"); sk2 = load_private(tmp / "keys2" / "other.private.pem")
base = build_raw_condition("corpus_full", "auto")
m1 = build_signed_manifest(base, sk, "corpus_full-auto", 1)
base2 = base + [{"id": "T9999", "description": "v2 addition"}]; m2 = build_signed_manifest(base2, sk, "corpus_full-auto", 2, manifest_sha256(m1))
state2 = {"max_version": 2, "manifest_sha256": manifest_sha256(m2)}
N = 300; res = {"n_trials_per_attack": N, "records": len(base), "signing_mode": "local-dev (Ed25519; key outside KB; NOT production key management)", "attacks": {}}
def run(name, make, expect_codes, state=None, key=pk):
    det = codes = 0
    for _ in range(N):
        recs, man = make()
        r = verify_kb(recs, man, key, state)
        det += (not r.ok); codes += bool(expect_codes & {k for k, _ in r.failures})
    res["attacks"][name] = {"detection_rate": det / N, "expected_failure_code_rate": codes / N, "expected_codes": sorted(expect_codes)}
def pick(): return rng.randrange(len(base))
def desc():
    r = copy.deepcopy(base); i = pick(); r[i]["description"] += rng.choice([" ", ".", " x"]); return r, m1
def rule():
    r = copy.deepcopy(base); i = pick(); r[i]["detection_signatures"] = {"falco": {"rule_name": "attacker", "trigger_condition": "true"}}; return r, m1
def repl_same():
    r = copy.deepcopy(base); i, j = pick(), pick(); r[i] = {**copy.deepcopy(r[j]), "id": r[i]["id"]}; return r, m1
def repl_swap():
    r = copy.deepcopy(base); i, j = rng.sample(range(len(base)), 2); r[i], r[j] = {**r[j], "id": r[i]["id"]}, {**r[i], "id": r[j]["id"]}; return r, m1
def dele():
    r = copy.deepcopy(base); del r[pick()]; return r, m1
def ins():
    r = copy.deepcopy(base); r.append({"id": f"TX{rng.randrange(10**6)}", "description": "injected"}); return r, m1
def man_mod():
    m = copy.deepcopy(m1); k = rng.choice(list(m["manifest"]["records"])); m["manifest"]["records"][k] = record_hash({"id": k, "evil": 1}); return base, m
def sig_mod():
    m = copy.deepcopy(m1); s = bytearray(base64.b64decode(m["signature_b64"])); s[rng.randrange(len(s))] ^= 1 << rng.randrange(8); m["signature_b64"] = base64.b64encode(bytes(s)).decode(); return base, m
def rollback(): return copy.deepcopy(base), m1
def wrong_key(): return base, build_signed_manifest(base, sk2, "corpus_full-auto", 1)
def fork(): 
    r = copy.deepcopy(base2); r[0]["description"] += "!"; return r, build_signed_manifest(r, sk, "corpus_full-auto", 2, manifest_sha256(m1))
def chain_break(): return base2, build_signed_manifest(base2, sk, "corpus_full-auto", 3, "f" * 64)
run("description_modification", desc, {"record_modified"}); run("rule_modification", rule, {"record_modified"}); run("record_replacement_same_id", repl_same, {"record_modified"})
run("record_replacement_content_swap", repl_swap, {"record_modified"}); run("record_deletion", dele, {"record_missing"}); run("record_insertion", ins, {"record_unexpected"})
run("manifest_modification", man_mod, {"signature_invalid"}); run("signature_modification", sig_mod, {"signature_invalid"}); run("rollback_to_old_signed_kb", rollback, {"rollback"}, state2)
run("invalid_signing_key", wrong_key, {"signature_invalid"}); run("fork_same_version", fork, {"fork_same_version"}, state2); run("chain_break_skipped_version", chain_break, {"chain_break"}, state2)
# false positives: benign re-serialisation (order, key order, NFC/NFD, whitespace-irrelevant) must verify
fp = 0
for _ in range(500):
    r = copy.deepcopy(base); rng.shuffle(r); r = [dict(rng.sample(list(x.items()), len(x))) for x in r]
    for x in r[:20]:
        if isinstance(x.get("description"), str) and rng.random() < .5: x["description"] = unicodedata.normalize("NFD", x["description"])
    fp += (not verify_kb(r, m1, pk).ok)
res["false_positive_rate_benign_reserialisation"] = {"rate": fp / 500, "trials": 500}
# semantic poisoning is NOT a cryptographic failure: poison BEFORE signing -> verifies; poison AFTER signing -> detected
pois = copy.deepcopy(base)
for i in rng.sample(range(len(base)), 4): pois[i]["description"] = base[(i + 1) % len(base)]["description"]
res["semantic_poisoning_boundary"] = {"poisoned_before_signing_verifies_ok": verify_kb(pois, build_signed_manifest(pois, sk, "x", 1), pk).ok,
                                      "poisoned_after_signing_detected": not verify_kb(pois, m1, pk).ok,
                                      "meaning": "Integrity protects the signed content only. Semantic poisoning of the signing source needs separate defences (see results_x/robustness.json, unchanged)."}
# latency / scaling
lat = []
for n in (706, 5000, 25000):
    recs = [{**base[i % len(base)], "id": f"{base[i % len(base)]['id']}#{i}"} for i in range(n)]
    t = time.perf_counter(); m = build_signed_manifest(recs, sk, "s", 1); ts = time.perf_counter() - t
    ts2 = []
    for _ in range(3): t = time.perf_counter(); r = verify_kb(recs, m, pk); ts2.append(time.perf_counter() - t); assert r.ok
    lat.append({"records": n, "sign_manifest_s": ts, "verify_s_median": float(np.median(ts2))})
res["latency"] = lat
(OUT3 / "m3_integrity_eval.json").write_text(json.dumps(res, indent=1)); print({k: v["detection_rate"] for k, v in res["attacks"].items()}, res["false_positive_rate_benign_reserialisation"], lat)
