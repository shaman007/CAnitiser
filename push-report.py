#!/usr/bin/env python3
import argparse
import json
import re
import sys
from typing import Any, Dict, List

from kubernetes import client, config
from kubernetes.client import CustomObjectsApi
from kubernetes.client.exceptions import ApiException

GROUP = "security.andreybondarenko.com"
VERSION = "v1alpha1"
PLURAL = "caimagereports"


def load_k8s() -> CustomObjectsApi:
    config.load_incluster_config()
    return client.CustomObjectsApi()


def build_spec(
    entries: List[Dict[str, Any]],
    scan_name: str,
    scan_namespace: str,
) -> Dict[str, Any]:
    total = len(entries)
    green = sum(1 for x in entries if x.get("status") == "GREEN")
    yellow = sum(1 for x in entries if x.get("status") == "YELLOW")
    red = sum(1 for x in entries if x.get("status") == "RED")

    return {
        "scanRef": {
            "name": scan_name,
            "namespace": scan_namespace,
        },
        "summary": {
            "totalImages": total,
            "green": green,
            "yellow": yellow,
            "red": red,
        },
        "report": entries,
    }


def upsert_report(
    api: CustomObjectsApi,
    name: str,
    namespace: str,
    spec: Dict[str, Any],
) -> None:
    try:
        api.get_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural=PLURAL,
            name=name,
        )
        exists = True
    except ApiException as e:
        if e.status == 404:
            exists = False
        else:
            raise

    if exists:
        sys.stderr.write(
            f"[push-report] patching existing {PLURAL}/{name} in {namespace}\n"
        )
        api.patch_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural=PLURAL,
            name=name,
            body={"spec": spec},
        )
    else:
        sys.stderr.write(
            f"[push-report] creating new {PLURAL}/{name} in {namespace}\n"
        )
        body = {
            "apiVersion": f"{GROUP}/{VERSION}",
            "kind": "CaImageReport",
            "metadata": {"name": name, "namespace": namespace},
            "spec": spec,
        }
        api.create_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural=PLURAL,
            body=body,
        )

    sys.stderr.write(f"[push-report] done for {name}\n")


def sanitize_ns(ns: str) -> str:
    """
    Make namespace safe for use in a resource name suffix.
    Lowercase and replace anything not [a-z0-9-] with '-'.
    """
    s = ns.lower()
    s = re.sub(r"[^a-z0-9-]", "-", s)
    return s or "unknown"


def main() -> None:
    p = argparse.ArgumentParser(
        description="Create/patch CaImageReport(s) from report.json, one per workload namespace.",
    )
    p.add_argument("--report-json", required=True)
    p.add_argument("--report-name", required=True)
    p.add_argument("--report-namespace", required=True)
    p.add_argument("--scan-name", required=True)
    p.add_argument("--scan-namespace", required=True)
    args = p.parse_args()

    with open(args.report_json, "r", encoding="utf-8") as f:
        full_report: List[Dict[str, Any]] = json.load(f)

    sys.stderr.write(
        f"[push-report] loaded {len(full_report)} entries from {args.report_json}\n"
    )

    # Group entries by workload namespace (entry["namespaces"])
    ns_map: Dict[str, List[Dict[str, Any]]] = {}

    for entry in full_report:
        ns_list = entry.get("namespaces") or []
        if not ns_list:
            # group under a synthetic "unknown" namespace if nothing is set
            ns_list = ["unknown"]

        for ns in ns_list:
            ns_map.setdefault(ns, []).append(entry)

    if not ns_map:
        sys.stderr.write("[push-report] no namespaces found in report; nothing to write\n")
        return

    api = load_k8s()

    # If there is exactly one namespace, keep the old name semantics:
    # use --report-name as-is for backward compatibility.
    if len(ns_map) == 1:
        only_ns, entries = next(iter(ns_map.items()))
        sys.stderr.write(
            f"[push-report] single namespace '{only_ns}', using name '{args.report_name}'\n"
        )
        spec = build_spec(entries, args.scan_name, args.scan_namespace)
        upsert_report(
            api=api,
            name=args.report_name,
            namespace=args.report_namespace,
            spec=spec,
        )
        return

    # Multi-namespace: create one CaImageReport per namespace, with name
    # "<report-name>-<namespace>" (sanitized).
    for ns, entries in ns_map.items():
        safe_ns = sanitize_ns(ns)
        cr_name = f"{args.report_name}-{safe_ns}"
        sys.stderr.write(
            f"[push-report] namespace '{ns}' -> {PLURAL}/{cr_name} "
            f"({len(entries)} images)\n"
        )
        spec = build_spec(entries, args.scan_name, args.scan_namespace)
        upsert_report(
            api=api,
            name=cr_name,
            namespace=args.report_namespace,
            spec=spec,
        )


if __name__ == "__main__":
    main()
