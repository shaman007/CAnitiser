#!/usr/bin/env python3
import argparse
import json
from kubernetes import client, config
from kubernetes.client import CustomObjectsApi
from kubernetes.client.exceptions import ApiException


GROUP = "security.andreybondarenko.com"
VERSION = "v1alpha1"
PLURAL = "caimagereports"


def load_k8s() -> CustomObjectsApi:
    # in-cluster
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

    body = {
        "apiVersion": f"{GROUP}/{VERSION}",
        "kind": "CaImageReport",
        "metadata": {
            "name": name,
            "namespace": namespace,
        },
        "spec": spec,
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
        api.patch_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural=PLURAL,
            name=name,
            body={"spec": spec},
        )
    else:
        api.create_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            namespace=namespace,
            plural=PLURAL,
            body=body,
        )


def main() -> None:
    p = argparse.ArgumentParser(description="Create/patch CaImageReport from report.json")
    p.add_argument("--report-json", required=True, help="Path to report.json (from ca-analyse.py)")
    p.add_argument("--report-name", required=True, help="Name of CaImageReport object")
    p.add_argument("--report-namespace", required=True, help="Namespace of CaImageReport object")
    p.add_argument("--scan-name", required=True, help="Origin CaImageScan or logical scan name")
    p.add_argument("--scan-namespace", required=True, help="Namespace of scan resource")
    args = p.parse_args()

    with open(args.report_json, "r", encoding="utf-8") as f:
        report = json.load
