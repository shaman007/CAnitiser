#!/usr/bin/env python3
import argparse
import json
import sys
from typing import Any, Dict, List


def load_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: failed to read JSON from {path}: {e}", file=sys.stderr)
        sys.exit(1)


def match_patterns(subject: str, patterns: List[str]) -> List[str]:
    s = subject.lower()
    hits = []
    for p in patterns:
        if p and p.lower() in s:
            hits.append(p)
    return hits


def classify_image(
    image_entry: Dict[str, Any],
    whitelist: List[str],
    blacklist: List[str],
) -> Dict[str, Any]:

    certs = image_entry.get("certs", []) or []

    blacklist_matches = []
    whitelist_matches = []
    not_matched = []

    # ---- NEW RULE HERE ----
    # No certs at all = GREEN
    if len(certs) == 0:
        return {
            "image": image_entry.get("image"),
            "namespaces": image_entry.get("namespaces", []),
            "status": "GREEN",
            "blacklist_matches": [],
            "whitelist_matches": [],
            "not_matched": [],
        }
    # -----------------------

    for cert in certs:
        subj = cert.get("subject", "") or ""
        path = cert.get("path", "") or ""

        bl = match_patterns(subj, blacklist)
        wl = match_patterns(subj, whitelist)

        if bl:
            for pat in bl:
                blacklist_matches.append({"pattern": pat, "path": path, "subject": subj})
        elif wl:
            for pat in wl:
                whitelist_matches.append({"pattern": pat, "path": path, "subject": subj})
        else:
            not_matched.append({"path": path, "subject": subj})

    # Status:
    # RED → any blacklist
    # GREEN → no blacklist AND some whitelist
    # YELLOW → otherwise
    if blacklist_matches:
        status = "RED"
    elif whitelist_matches:
        status = "GREEN"
    else:
        status = "YELLOW"

    return {
        "image": image_entry.get("image"),
        "namespaces": image_entry.get("namespaces", []),
        "status": status,
        "blacklist_matches": blacklist_matches,
        "whitelist_matches": whitelist_matches,
        "not_matched": not_matched,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyse certs JSON with whitelist/blacklist.")
    parser.add_argument("--images", required=True, help="JSON from ca-nitiser.py")
    parser.add_argument("--policy", required=False, help="policy.json with whitelist/blacklist")
    args = parser.parse_args()

    images = load_json(args.images)

    if args.policy:
        pol = load_json(args.policy)
        whitelist = pol.get("whitelist", []) or []
        blacklist = pol.get("blacklist", []) or []
    else:
        whitelist = ["Let's Encrypt", "ISRG Root X1"]
        blacklist = ["COMODO", "Comodo", "China", "CNNIC", "TeliaSonera", "Telia Sonera"]

    results = [classify_image(img, whitelist, blacklist) for img in images]

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()

