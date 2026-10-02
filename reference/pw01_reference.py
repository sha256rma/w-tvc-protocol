"""Measure the PW-01 tokenizer reference for every model in plan.json.

Usage:
    python3 pw01_reference.py            # needs: pip install tokenizers

For each model: download tokenizer.json at the pinned commit, record its
SHA-256, and count the tokens of each string in batteries/pw01-tokenizer-v1.json
with add_special_tokens=False. Gated models are recorded as blocked unless
HF_TOKEN is set and the licence has been accepted.

Writes runs/pw01-tokenizer-v1.json. Every number in it is measured here.
"""
import hashlib
import json
import os
import platform
import time
import urllib.error
import urllib.request

from tokenizers import Tokenizer

HERE = os.path.dirname(os.path.abspath(__file__))


def fetch(repo: str, commit: str) -> bytes:
    request = urllib.request.Request(
        f"https://huggingface.co/{repo}/resolve/{commit}/tokenizer.json",
        headers={"User-Agent": "w-tvc-reference/1"},
    )
    token = os.environ.get("HF_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token.strip()}")
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def main() -> None:
    plan = json.load(open(os.path.join(HERE, "plan.json")))
    battery = json.load(open(os.path.join(HERE, "batteries", "pw01-tokenizer-v1.json")))
    texts = [item["text"] for item in battery["items"]]

    results = []
    for model in plan["models"]:
        row = {"model": model["id"], "hf_repo": model["hf_repo"], "hf_commit": model["hf_commit"]}
        started = time.perf_counter()
        try:
            raw = fetch(model["hf_repo"], model["hf_commit"])
        except urllib.error.HTTPError as error:
            row["status"] = "blocked"
            row["reason"] = (
                f"HTTP {error.code}: gated, needs HF_TOKEN and an accepted licence"
                if error.code in (401, 403)
                else f"HTTP {error.code}"
            )
            results.append(row)
            print(f"{model['id']:<22} blocked ({row['reason']})")
            continue
        fetched = time.perf_counter()
        tokenizer = Tokenizer.from_str(raw.decode("utf-8"))
        counts = [len(tokenizer.encode(text, add_special_tokens=False).ids) for text in texts]
        done = time.perf_counter()
        row.update(
            status="measured",
            tokenizer_sha256=hashlib.sha256(raw).hexdigest(),
            tokenizer_bytes=len(raw),
            vocab_size=tokenizer.get_vocab_size(with_added_tokens=True),
            counts=counts,
            total_tokens=sum(counts),
            fetch_s=round(fetched - started, 3),
            encode_s=round(done - fetched, 4),
        )
        results.append(row)
        print(f"{model['id']:<22} total={sum(counts):>4}  counts={counts}")

    measured = {r["model"]: r for r in results if r["status"] == "measured"}
    pairs = []
    for pair in plan["pairs"]:
        a, b = measured.get(pair["claimed"]), measured.get(pair["served"])
        if pair["served"] not in {m["id"] for m in plan["models"]}:
            pairs.append({**pair, "separates": "n/a",
                          "reason": "same weights in a different configuration; not a tokenizer question"})
            continue
        if not a or not b:
            pairs.append({**pair, "separates": "not run", "reason": "one side not measured"})
            continue
        differing = [
            battery["items"][i]["name"]
            for i, (x, y) in enumerate(zip(a["counts"], b["counts"]))
            if x != y
        ]
        pairs.append({
            **pair,
            "separates": "yes" if differing else "no",
            "items_that_differ": differing,
            "margin_tokens": sum(abs(x - y) for x, y in zip(a["counts"], b["counts"])),
        })

    # Which models a PW-01 result alone could tell apart: models with identical
    # count vectors are indistinguishable to this check.
    groups = {}
    for row in measured.values():
        groups.setdefault(json.dumps(row["counts"]), []).append(row["model"])

    out = {
        "kind": "reference-measurement/v1",
        "battery": battery["id"],
        "check": battery["check"],
        "measured_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "machine": f"{platform.machine()} {platform.system()} {platform.release()}, CPU only",
        "tool": "huggingface tokenizers",
        "models": results,
        "pairs": pairs,
        "indistinguishable_groups": [g for g in groups.values() if len(g) > 1],
    }
    path = os.path.join(HERE, "runs", "pw01-tokenizer-v1.json")
    json.dump(out, open(path, "w"), indent=1, ensure_ascii=False)
    print(f"\nwrote {path}")
    for pair in pairs:
        print(f"  {pair['claimed']:>20} vs {pair['served']:<26} separates={pair['separates']}")
    print("  indistinguishable by PW-01:", out["indistinguishable_groups"])


if __name__ == "__main__":
    main()
