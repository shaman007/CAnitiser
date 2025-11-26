#!/usr/bin/env python3
import argparse
import json
import time
import hashlib
from typing import Dict, List, Any, Optional

from kubernetes import client, config
from kubernetes.client import CoreV1Api, BatchV1Api


CA_PATHS_DEFAULT = [
    "/etc/ssl/certs",
    "/etc/pki",
    "/usr/local/share/ca-certificates",
]


def load_k8s() -> tuple[CoreV1Api, BatchV1Api]:
    # in-cluster config
    config.load_incluster_config()
    return client.CoreV1Api(), client.BatchV1Api()


def get_images_and_namespaces(
    core: CoreV1Api,
    scope_namespace: Optional[str],
) -> Dict[str, Any]:
    """
    image -> { "namespaces": set([...]) }
    """
    if scope_namespace:
        pods = core.list_namespaced_pod(scope_namespace)
    else:
        pods = core.list_pod_for_all_namespaces()

    images: Dict[str, Any] = {}

    for p in pods.items:
        ns = p.metadata.namespace
        spec = p.spec or {}

        def handle(cont_list):
            for c in cont_list or []:
                img = c.image
                if not img:
                    continue
                images.setdefault(img, {"namespaces": set()})
                images[img]["namespaces"].add(ns)

        handle(spec.containers)
        handle(spec.init_containers)
        handle(getattr(spec, "ephemeral_containers", None))

    return images


def make_job_name(image: str) -> str:
    h = hashlib.sha1(image.encode("utf-8")).hexdigest()[:8]
    return f"ca-scan-{h}"


def build_shell_script(ca_paths: List[str]) -> str:
    ca_paths_arg = " ".join(ca_paths)
    return f"""
set -e
for base in {ca_paths_arg}; do
  if [ -d "$base" ]; then
    find "$base" -type f 2>/dev/null | while read f; do
      sub=$(openssl x509 -in "$f" -noout -subject 2>/dev/null || true)
      if [ -n "$sub" ]; then
        printf '%s\\t%s\\n' "$f" "$sub"
      fi
    done
  fi
done
"""


def create_scan_job(
    batch: BatchV1Api,
    scan_ns: str,
    image: str,
    shell_script: str,
) -> str:
    name = make_job_name(image)

    job = client.V1Job(
        api_version="batch/v1",
        kind="Job",
        metadata=client.V1ObjectMeta(
            name=name,
            namespace=scan_ns,
            labels={"app": "ca-scan"},
        ),
        spec=client.V1JobSpec(
            backoff_limit=0,
            template=client.V1PodTemplateSpec(
                metadata=client.V1ObjectMeta(
                    labels={"job-name": name, "app": "ca-scan"},
                ),
                spec=client.V1PodSpec(
                    restart_policy="Never",
                    containers=[
                        client.V1Container(
                            name="scan",
                            image=image,
                            command=["sh", "-c", shell_script],
                        )
                    ],
                ),
            ),
        ),
    )

    batch.create_namespaced_job(namespace=scan_ns, body=job)
    return name


def wait_for_job(
    batch: BatchV1Api,
    scan_ns: str,
    job_name: str,
    timeout_sec: int = 180,
) -> str:
    """
    Return "Complete", "Failed", "Timeout".
    """
    start = time.time()
    while True:
        if time.time() - start > timeout_sec:
            return "Timeout"

        job = batch.read_namespaced_job(name=job_name, namespace=scan_ns)
        conds = {c.type: c.status for c in (job.status.conditions or [])}
        if conds.get("Complete") == "True":
            return "Complete"
        if conds.get("Failed") == "True":
            return "Failed"
        time.sleep(2)


def get_job_pod_name(core: CoreV1Api, scan_ns: str, job_name: str) -> Optional[str]:
    pods = core.list_namespaced_pod(
        namespace=scan_ns,
        label_selector=f"job-name={job_name}",
    )
    if not pods.items:
        return None
    return pods.items[0].metadata.name


def get_pod_logs(core: CoreV1Api, scan_ns: str, pod_name: str) -> str:
    return core.read_namespaced_pod_log(name=pod_name, namespace=scan_ns) or ""


def delete_job(batch: BatchV1Api, scan_ns: str, job_name: str) -> None:
    propagation = client.V1DeleteOptions(
        propagation_policy="Foreground",
    )
    try:
        batch.delete_namespaced_job(
            name=job_name,
            namespace=scan_ns,
            body=propagation,
        )
    except Exception:
        pass


def extract_certs_with_job(
    core: CoreV1Api,
    batch: BatchV1Api,
    scan_ns: str,
    image: str,
    ca_paths: List[str],
) -> List[Dict[str, str]]:
    shell_script = build_shell_script(ca_paths)
    job_name = create_scan_job(batch, scan_ns, image, shell_script)

    try:
        phase = wait_for_job(batch, scan_ns, job_name)
        if phase != "Complete":
            return []

        pod_name = get_job_pod_name(core, scan_ns, job_name)
        if not pod_name:
            return []

        logs = get_pod_logs(core, scan_ns, pod_name)
        certs: List[Dict[str, str]] = []
        for line in logs.splitlines():
            if "\t" not in line:
                continue
            path, subject = line.split("\t", 1)
            certs.append({"path": path, "subject": subject})
        return certs
    finally:
        delete_job(batch, scan_ns, job_name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract CA certificates from K8S images using per-image Jobs (no kubectl).",
    )
    parser.add_argument(
        "--scan-namespace",
        default="ca-scanner",
        help="Namespace to create scan Jobs in (default: ca-scanner)",
    )
    parser.add_argument(
        "--namespace",
        default=None,
        help="Limit discovery to a single namespace (default: all namespaces)",
    )
    parser.add_argument(
        "--ca-path",
        action="append",
        dest="ca_paths",
        help="Extra CA search path (can be repeated).",
    )
    args = parser.parse_args()

    ca_paths = CA_PATHS_DEFAULT.copy()
    if args.ca_paths:
        ca_paths.extend(args.ca_paths)

    core, batch = load_k8s()

    images_info = get_images_and_namespaces(core, args.namespace)

    result = []
    for image, info in sorted(images_info.items(), key=lambda kv: kv[0]):
        ns_set = info["namespaces"]
        certs = extract_certs_with_job(core, batch, args.scan_namespace, image, ca_paths)

        result.append(
            {
                "image": image,
                "namespaces": sorted(ns_set),
                "certs": certs,
            }
        )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
