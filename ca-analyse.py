#!/usr/bin/env python3
import argparse
import json
from typing import Any, Dict, List


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def classify_cert(
    subject: str,
    whitelist: List[str],
    blacklist: List[str],
) -> str:
    """
    Return: 'red', 'green', or 'not_matched'
    - blacklist wins over whitelist if both match
    """
    s = subject.lower()

    for pat in blacklist:
        if pat.lower() in s:
            return "red"

    for pat in whitelist:
        if pat.lower() in s:
            return "green"

    return "not_matched"


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

        # image-level status
        has_red = any(c["classification"] == "red" for c in flat_certs)
        has_not_matched = any(c["classification"] == "not_matched" for c in flat_certs)

        if has_red:
            status = "RED"
        elif flat_certs and has_not_matched:
            status = "YELLOW"
        else:
            # no certs OR all green
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
