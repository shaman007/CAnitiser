#!/usr/bin/env python3
import argparse
import json
import sys
from kubernetes import client, config
from kubernetes.client import CustomObjectsApi
from kubernetes.client.exceptions import ApiException

GROUP = "canitiser.io"
VERSION = "v1alpha1"
PLURAL = "caimagereports"


def load_k8s() -> CustomObjectsApi:
    config.load_incluster_config()
    return client.CustomObjectsApi()


def upsert_report(
    api: CustomObjectsApi,
    name: str,
    namespace: str,
    scan_name: str,
    scan_namespace: str,
    report: list[dict],
) -> None:
    total = len(report)
    green = sum(1 for x in report if x.get("status") == "GREEN")
    yellow = sum(1 for x in report if x.get("status") == "YELLOW")
    red = sum(1 for x in report if x.get("status") == "RED")

    sys.stderr.write(
        f"[push-report] building spec: total={total}, green={green}, yellow={yellow}, red={red}\n"
    )

    spec = {
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
        "report": report,
    }

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

    sys.stderr.write("[push-report] done\n")


def main() -> None:
    p = argparse.ArgumentParser(description="Create/patch CaImageReport from report.json")
    p.add_argument("--report-json", required=True)
    p.add_argument("--report-name", required=True)
    p.add_argument("--report-namespace", required=True)
    p.add_argument("--scan-name", required=True)
    p.add_argument("--scan-namespace", required=True)
    args = p.parse_args()

    with open(args.report_json, "r", encoding="utf-8") as f:
        report = json.load(f)

    sys.stderr.write(
        f"[push-report] loaded report with {len(report)} entries from {args.report_json}\n"
    )

    api = load_k8s()
    upsert_report(
        api=api,
        name=args.report_name,
        namespace=args.report_namespace,
        scan_name=args.scan_name,
        scan_namespace=args.scan_namespace,
        report=report,
    )


if __name__ == "__main__":
    main()
