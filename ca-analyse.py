#!/usr/bin/env python3
import argparse
import json
import sys
from typing import Any, Dict, List


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ca-analyse] Failed to parse JSON {path}: {e}", file=sys.stderr)
            raise


def normalize_subject(subject: str) -> str:
    s = subject.strip()
    if s.lower().startswith("subject="):
        s = s[len("subject="):].lstrip()
    return s.lower()


def classify_cert(
    subject: str,
    whitelist: List[str],
    blacklist: List[str],
) -> str:
    """
    Return exact labels: 'RED', 'GREEN', or 'YELLOW'
    - blacklist wins over whitelist if both match
    """
    s = normalize_subject(subject)

    for pat in blacklist:
        if pat.lower() in s:
            return "RED"

    for pat in whitelist:
        if pat.lower() in s:
            return "GREEN"

    return "YELLOW"


def main() -> None:
    p = argparse.ArgumentParser(
        description="Analyse CA usage per image based on policy (whitelist/blacklist).",
    )
    p.add_argument(
        "--images",
        required=True,
        help="images.json from ca-nitiser (list of {image,namespaces,certs})",
    )
    p.add_argument(
        "--policy",
        required=True,
        help="policy.json with {whitelist: [...], blacklist: [...]}",
    )
    p.add_argument(
        "--out",
        default="-",
        help="Output file (default: stdout)",
    )
    args = p.parse_args()

    images_data = load_json(args.images)
    policy = load_json(args.policy)

    whitelist = policy.get("whitelist", [])
    blacklist = policy.get("blacklist", [])

    report: List[Dict[str, Any]] = []

    for entry in images_data:
        image = entry.get("image")
        namespaces = entry.get("namespaces", [])
        certs_raw = entry.get("certs", [])

        flat_certs: List[Dict[str, str]] = []

        for cert in certs_raw:
            subj = cert.get("subject", "")
            cls = classify_cert(subj, whitelist, blacklist)
            flat_certs.append(
                {
                    "path": cert.get("path", ""),
                    "subject": subj,
                    "classification": cls,
                }
            )

        has_red = any(c["classification"] == "RED" for c in flat_certs)
        has_yellow = any(c["classification"] == "YELLOW" for c in flat_certs)

        if has_red:
            status = "RED"
        elif flat_certs and has_yellow:
            status = "YELLOW"
        else:
            # no certs OR all GREEN
            status = "GREEN"

        report.append(
            {
                "image": image,
                "namespaces": namespaces,
                "status": status,
                "certs": flat_certs,
            }
        )

    out_json = json.dumps(report, indent=2)

    if args.out == "-" or args.out == "/dev/stdout":
        print(out_json)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_json)


if __name__ == "__main__":
    main()
