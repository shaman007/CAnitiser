#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time
import hashlib
from typing import Dict, List, Any, Optional

CONFIG = {
    "kubectl_cmd": ["kubectl"],
    "ca_paths": [
        "/etc/ssl/certs",
        "/etc/pki",
        "/usr/local/share/ca-certificates",
    ],
    # namespace where scan Jobs will run
    "scan_namespace": "ca-scanner",
}


def run(cmd: List[str], input_bytes: Optional[bytes] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def get_images_and_namespaces(
    kubectl_cmd: List[str],
    scope_namespace: Optional[str],
) -> Dict[str, Any]:
    """
    Returns:
      image -> {"namespaces": set([...])}
    """
    if scope_namespace:
        cmd = kubectl_cmd + ["get", "pods", "-n", scope_namespace, "-o", "json"]
    else:
        cmd = kubectl_cmd + ["get", "pods", "-A", "-o", "json"]

    proc = run(cmd)
    if proc.returncode != 0:
        print("ERROR: kubectl get pods failed:", proc.stderr.decode(), file=sys.stderr)
        sys.exit(1)

    data = json.loads(proc.stdout.decode() or "{}")
    images: Dict[str, Any] = {}

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        ns = meta.get("namespace", "default")

        def handle_containers(key: str):
            for c in spec.get(key, []) or []:
                image = c.get("image")
                if not image:
                    continue
                images.setdefault(image, {"namespaces": set()})
                images[image]["namespaces"].add(ns)

        handle_containers("containers")
        handle_containers("initContainers")
        handle_containers("ephemeralContainers")

    return images


def make_job_name(image: str) -> str:
    h = hashlib.sha1(image.encode("utf-8")).hexdigest()[:8]
    return f"ca-scan-{h}"


def json_to_yaml(obj: Any) -> str:
    # kubectl accepts JSON as YAML via -f -, so we can just dump JSON
    return json.dumps(obj)


def create_scan_job(
    kubectl_cmd: List[str],
    scan_ns: str,
    image: str,
    ca_paths: List[str],
) -> str:
    """
    Create a Job that runs the image, prints certs to stdout.
    Returns job name or "" on failure.
    """
    job_name = make_job_name(image)
    ca_paths_arg = " ".join(ca_paths)

    shell_script = f"""
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

    job_manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": scan_ns,
            "labels": {
                "app": "ca-scan",
            },
        },
        "spec": {
            "backoffLimit": 0,
            "template": {
                "metadata": {
                    "labels": {
                        "job-name": job_name,
                    },
                },
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "scan",
                            "image": image,
                            "command": ["sh", "-c", shell_script],
                        }
                    ],
                },
            },
        },
    }

    manifest_yaml = json_to_yaml(job_manifest)
    proc = run(
        kubectl_cmd + ["apply", "-f", "-"],
        input_bytes=manifest_yaml.encode("utf-8"),
    )
    if proc.returncode != 0:
        # print(proc.stderr.decode(), file=sys.stderr)
        return ""
    return job_name


def wait_for_job_done(
    kubectl_cmd: List[str],
    scan_ns: str,
    job_name: str,
    timeout_sec: int = 180,
) -> str:
    """
    Wait for Job to complete or fail.
    Returns "Complete", "Failed", "Timeout", or "Unknown".
    """
    start = time.time()
    while True:
        if time.time() - start > timeout_sec:
            return "Timeout"

        proc = run(
            kubectl_cmd
            + ["get", "job", job_name, "-n", scan_ns, "-o", "json"]
        )
        if proc.returncode != 0:
            # maybe not created yet or already gone
            time.sleep(2)
            continue

        data = json.loads(proc.stdout.decode() or "{}")
        conditions = data.get("status", {}).get("conditions", []) or []
        conds = {c.get("type"): c.get("status") for c in conditions}
        if conds.get("Complete") == "True":
            return "Complete"
        if conds.get("Failed") == "True":
            return "Failed"

        time.sleep(2)


def get_job_pod_name(
    kubectl_cmd: List[str],
    scan_ns: str,
    job_name: str,
) -> Optional[str]:
    proc = run(
        kubectl_cmd
        + ["get", "pods", "-n", scan_ns, "-l", f"job-name={job_name}", "-o", "json"]
    )
    if proc.returncode != 0:
        return None
    data = json.loads(proc.stdout.decode() or "{}")
    items = data.get("items", [])
    if not items:
        return None
    return items[0].get("metadata", {}).get("name")


def get_pod_logs(
    kubectl_cmd: List[str],
    scan_ns: str,
    pod_name: str,
) -> str:
    proc = run(
        kubectl_cmd
        + ["logs", "-n", scan_ns, pod_name]
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode()


def delete_job(
    kubectl_cmd: List[str],
    scan_ns: str,
    job_name: str,
) -> None:
    run(
        kubectl_cmd
        + ["delete", "job", job_name, "-n", scan_ns, "--ignore-not-found=true"]
    )


def extract_certs_with_job(
    kubectl_cmd: List[str],
    scan_ns: str,
    image: str,
    ca_paths: List[str],
) -> List[Dict[str, str]]:
    job_name = create_scan_job(kubectl_cmd, scan_ns, image, ca_paths)
    if not job_name:
        return []

    try:
        phase = wait_for_job_done(kubectl_cmd, scan_ns, job_name)
        if phase != "Complete":
            return []

        pod_name = get_job_pod_name(kubectl_cmd, scan_ns, job_name)
        if not pod_name:
            return []

        logs = get_pod_logs(kubectl_cmd, scan_ns, pod_name)
        certs: List[Dict[str, str]] = []
        for line in logs.splitlines():
            if "\t" not in line:
                continue
            path, subject = line.split("\t", 1)
            certs.append({"path": path, "subject": subject})
        return certs
    finally:
        delete_job(kubectl_cmd, scan_ns, job_name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract CA certificates from K8S images using per-image Jobs → JSON",
    )
    parser.add_argument(
        "--kubectl",
        nargs="+",
        default=CONFIG["kubectl_cmd"],
        help="kubectl command (default: %(default)s)",
    )
    parser.add_argument(
        "--scan-namespace",
        default=CONFIG["scan_namespace"],
        help="Namespace to create scan Jobs in (default: %(default)s)",
    )
    parser.add_argument(
        "--namespace",
        default=None,
        help="Limit scan to a single namespace (default: all namespaces)",
    )
    args = parser.parse_args()

    kubectl_cmd = args.kubectl
    ca_paths = CONFIG["ca_paths"]
    scan_ns = args.scan_namespace
    scope_ns = args.namespace

    images_info = get_images_and_namespaces(kubectl_cmd, scope_ns)

    result = []
    for image, info in sorted(images_info.items(), key=lambda kv: kv[0]):
        ns_set = info["namespaces"]

        certs = extract_certs_with_job(
            kubectl_cmd,
            scan_ns,
            image,
            ca_paths,
        )

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
