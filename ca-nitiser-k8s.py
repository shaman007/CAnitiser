#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
import time
from typing import Any, Dict, List, Optional

from kubernetes import client, config
from kubernetes.client import CoreV1Api, BatchV1Api
from kubernetes.client.exceptions import ApiException

SCAN_NAMESPACE_DEFAULT = "ca-scanner"
SCANNER_IMAGE_DEFAULT = "harbor.andreybondarenko.com/library/ca-scanner-base:latest"


def load_k8s() -> tuple[CoreV1Api, BatchV1Api]:
    # In-cluster config
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
    h = hashlib.sha1(image.encode("utf-8")).hexdigest()[:10]
    return f"ca-scan-{h}"


def build_scan_shell_script() -> str:
    return r"""
set -e

IMAGE="${TARGET_IMAGE:?TARGET_IMAGE not set}"
WORK="/work"
OCI_DIR="$WORK/oci"
ROOT_DIR="$WORK/root"

mkdir -p "$OCI_DIR" "$ROOT_DIR"

if ! command -v skopeo >/dev/null 2>&1; then
  echo "skopeo not found, no scan" >&2
  exit 0
fi

if ! command -v umoci >/dev/null 2>&1; then
  echo "umoci not found, no scan" >&2
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl not found, no scan" >&2
  exit 0
fi

echo "Pulling image: $IMAGE" >&2
skopeo copy \
  --insecure-policy \
  "docker://$IMAGE" \
  "oci:$OCI_DIR:scan" >/dev/null 2>&1 || {
    echo "skopeo copy failed for $IMAGE" >&2
    exit 0
  }

echo "Unpacking image with umoci" >&2
umoci unpack --rootless --image "$OCI_DIR:scan" "$ROOT_DIR" >/dev/null 2>&1 || {
  echo "umoci unpack failed for $IMAGE" >&2
  exit 0
}

ROOTFS="$ROOT_DIR/rootfs"

scan_path() {
  base="$1"
  if [ -d "$ROOTFS$base" ]; then
    find "$ROOTFS$base" 2>/dev/null | while read f; do
      sub="$(openssl x509 -in "$f" -noout -subject>/dev/null || true)"
      if [ -n "$sub" ]; then
        rel="${f#$ROOTFS}"
        printf '%s\t%s\n' "$rel" "$sub"
      fi
    done
  fi
}

for base in /etc/ssl/certs /etc/pki /usr/local/share/ca-certificates; do
  scan_path "$base"
done
"""


def create_scan_job(
    batch: BatchV1Api,
    scan_ns: str,
    image: str,
    scanner_image: str,
) -> str:
    from kubernetes.client.exceptions import ApiException

    name = make_job_name(image)
    shell_script = build_scan_shell_script()

    # Single container, no volumes needed
    scan_container = client.V1Container(
        name="scan",
        image=scanner_image,
        command=["/bin/sh", "-c", shell_script],
        env=[client.V1EnvVar(name="TARGET_IMAGE", value=image)],
    )

    pod_spec = client.V1PodSpec(
        restart_policy="Never",
        containers=[scan_container],
    )

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
                spec=pod_spec,
            ),
        ),
    )

    try:
        batch.create_namespaced_job(namespace=scan_ns, body=job)
    except ApiException as e:
        if e.status == 409:
            sys.stderr.write(
                f"[nitiser] job {name} already exists in {scan_ns}, reusing\n"
            )
        else:
            raise

    return name



def wait_for_job(
    batch: BatchV1Api,
    scan_ns: str,
    job_name: str,
    timeout_sec: int = 600,
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


def get_pod_logs(
    core: CoreV1Api,
    scan_ns: str,
    pod_name: str,
    container: str = "dump",
) -> str:
    try:
        return core.read_namespaced_pod_log(
            name=pod_name,
            namespace=scan_ns,
            container=container,
        ) or ""
    except Exception:
        return ""

def extract_certs_with_job(
    core: CoreV1Api,
    batch: BatchV1Api,
    scan_ns: str,
    image: str,
    scanner_image: str,
) -> List[Dict[str, str]]:
    job_name = create_scan_job(batch, scan_ns, image, scanner_image)

    phase = wait_for_job(batch, scan_ns, job_name)
    pod_name = get_job_pod_name(core, scan_ns, job_name)

    if not pod_name:
        print(f"WARN: no pod for job {job_name} (image {image})", file=sys.stderr)
        return []

    # logs from the single 'scan' container
    logs = get_pod_logs(core, scan_ns, pod_name, container="scan")

    if phase != "Complete":
        print(f"WARN: scan job for image {image} ended with phase {phase}", file=sys.stderr)
        if logs:
            for line in logs.splitlines()[:20]:
                print(f"  [scan-log] {line}", file=sys.stderr)
        return []

    logs = logs.strip()
    if not logs:
        return []

    certs: List[Dict[str, str]] = []
    for line in logs.splitlines():
        # skip progress lines like "Pulling image..."
        if "\t" not in line:
            continue
        path, subj = line.split("\t", 1)
        path = path.strip()
        subj = subj.strip()
        if path and subj:
            certs.append({"path": path, "subject": subj})

    return certs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract CA certs from images using in-cluster Jobs (skopeo+umoci).",
    )
    parser.add_argument(
        "--scan-namespace",
        default=SCAN_NAMESPACE_DEFAULT,
        help=f"Namespace to create scan Jobs in (default: {SCAN_NAMESPACE_DEFAULT})",
    )
    parser.add_argument(
        "--namespace",
        default=None,
        help="Limit discovery to a single namespace (default: all namespaces)",
    )
    parser.add_argument(
        "--scanner-image",
        default=SCANNER_IMAGE_DEFAULT,
        help=f"Image used as scanner (with skopeo+umoci+openssl). Default: {SCANNER_IMAGE_DEFAULT}",
    )
    args = parser.parse_args()

    core, batch = load_k8s()
    images_info = get_images_and_namespaces(core, args.namespace)

    # debug to stderr so you see what it found
    sys.stderr.write(f"[nitiser] found {len(images_info)} unique images\n")

    result = []
    for image, info in sorted(images_info.items(), key=lambda kv: kv[0]):
        ns_set = info["namespaces"]
        sys.stderr.write(f"[nitiser] scanning image: {image}\n")

        certs = extract_certs_with_job(
            core=core,
            batch=batch,
            scan_ns=args.scan_namespace,
            image=image,
            scanner_image=args.scanner_image,
        )

        sys.stderr.write(
            f"[nitiser] image {image}: {len(certs)} certs\n"
        )

        result.append(
            {
                "image": image,
                "namespaces": sorted(ns_set),
                "certs": certs,
            }
        )

    # ✔ always print JSON to stdout
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
