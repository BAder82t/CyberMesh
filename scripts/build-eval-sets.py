"""Builds evaluation evidence and labelled splits from eval-data/raw (run with python3 -I).

Design (temporal, leakage-aware):
  * reference feed  = phishing snapshot T0 (what a feed-only service knows at T0)
  * malicious/new   = domains in snapshot T1 that are absent from T0: phishing that appeared
                      after T0, i.e. unknown to the feed baseline
  * malicious/known = sample of T0 domains (the baseline's home turf, for coverage checks)
  * benign          = Majestic Million ranks 20,001..1,000,000 (outside the popularity list,
                      which is ranks 1..10,000), minus anything listed in T0 or T1
  * split           = sha256(domain) bucket: 0-5 dev, 6-7 validation, 8-9 heldout
Engine weights were fixed before this data was examined; no tuning used validation/heldout.
"""
import csv, hashlib, json, os, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "eval-data", "raw")
OUT = os.path.join(ROOT, "eval-data")
BENIGN_N = 60000
KNOWN_N = 20000

def domains(path):
    out = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            d = line.strip().lower().rstrip(".")
            if not d or d.startswith("#") or "/" in d or ":" in d:
                continue
            if d.replace(".", "").isdigit():
                continue
            out.add(d)
    return out

def bucket(d):
    return hashlib.sha256(d.encode()).digest()[0] % 10

def split(d):
    b = bucket(d)
    return "dev" if b <= 5 else ("validation" if b <= 7 else "heldout")

def sample(items, n, salt):
    return sorted(items, key=lambda d: hashlib.sha256((salt + d).encode()).digest())[:n]

t0 = domains(os.path.join(RAW, "phishing-t0.txt"))
t1 = domains(os.path.join(RAW, "phishing-t1.txt"))
new = t1 - t0
majestic = []
with open(os.path.join(RAW, "majestic_million.csv"), encoding="utf-8", errors="replace") as f:
    r = csv.reader(f)
    next(r)
    for row in r:
        majestic.append((int(row[0]), row[2].strip().lower()))
popular = [d for rank, d in majestic if rank <= 10000]
benign_pool = [d for rank, d in majestic if 20000 < rank <= 1000000 and d not in t0 and d not in t1]
benign = sample(benign_pool, BENIGN_N, "benign")
known = sample(sorted(t0 & t1), KNOWN_N, "known")

ev = os.path.join(OUT, "evidence")
os.makedirs(ev, exist_ok=True)
with open(os.path.join(ev, "reference-feed.txt"), "w") as f:
    f.write("# Phishing.Database phishing-domains-ACTIVE.txt at T0 (MIT); evaluation only\n")
    f.write("\n".join(sorted(t0)) + "\n")
with open(os.path.join(ev, "popular-domains.txt"), "w") as f:
    f.write("\n".join(popular) + "\n")
for name in ("brands.json", "hosting-platforms.txt"):
    shutil.copy(os.path.join(ROOT, "datasets", "demo", "evidence", name), os.path.join(ev, name))
zero = "sha256:" + "0" * 64
bundle = {"v": 1, "sources": [
    {"id": "brands", "kind": "brands", "file": "brands.json", "sha256": zero, "version": "repo", "license": "Apache-2.0", "origin": "cybermesh"},
    {"id": "hosting-platforms", "kind": "hosting-platforms", "file": "hosting-platforms.txt", "sha256": zero, "version": "repo", "license": "Apache-2.0", "origin": "cybermesh"},
    {"id": "popularity", "kind": "popularity", "file": "popular-domains.txt", "sha256": zero, "version": "majestic-top10k", "license": "CC-BY-3.0", "origin": "majestic"},
    {"id": "reference-feed", "kind": "blocklist", "file": "reference-feed.txt", "sha256": zero, "version": "phishing-database-t0", "license": "MIT", "origin": "mitchellkrogza/Phishing.Database"},
]}
with open(os.path.join(ev, "bundle.json"), "w") as f:
    json.dump(bundle, f, indent=2)

with open(os.path.join(OUT, "dataset.csv"), "w") as f:
    f.write("domain,label,split\n")
    for d in sorted(new):
        f.write(f"{d},malicious,{split(d)}\n")
    for d in benign:
        f.write(f"{d},benign,{split(d)}\n")
with open(os.path.join(OUT, "known.csv"), "w") as f:
    f.write("domain,label,split\n")
    for d in known:
        f.write(f"{d},malicious,known\n")
stats = {"t0": len(t0), "t1": len(t1), "new_in_t1": len(new), "benign": len(benign), "known_sample": len(known), "popular": len(popular)}
json.dump(stats, open(os.path.join(OUT, "stats.json"), "w"), indent=2)
print(json.dumps(stats))
