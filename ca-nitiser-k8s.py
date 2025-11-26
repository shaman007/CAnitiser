#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time
import hashlib
from typing import Dict, List, Any

CONFIG = {
    "kubectl_cmd": ["kubectl"],
    "ca_paths": [
        "/etc/ssl/certs",
        "/etc/pki",
        "/usr/local/share/ca-certificates",
    ],
    # namespace where ephemeral scan pods will run
    "scan_namespace": "ca-scanner",
}


def run(cmd: List[str], input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def get_images_and_namespaces(kubectl_cmd: List[str]) -> Dict[str, Any]:
    """
    Returns mapping:
      image -> {
        "namespaces": set([...])
      }
    """
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


def make_pod_name(image: str) -> str:
    h = hashlib.sha1(image.encode("utf-8")).hexdigest()[:8]
    return f"ca-scan-{h}"


def create_scan_pod(
    kubectl_cmd: List[str],
    scan_ns: str,
    image: str,
    ca_paths: List[str],
) -> str:
    """
    Create a temporary pod in scan_ns that runs `sh -c <script>` inside the image.
    Returns pod name.
    """
    pod_name = make_pod_name(image)
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

    # Pod manifest
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": scan_ns,
            "labels": {
                "app": "ca-scan",
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
    }

    manifest_yaml = json_to_yaml(manifest)
    proc = run(kubectl_cmd + ["apply", "-f", "-"], input_bytes=manifest_yaml.encode("utf-8"))
    if proc.returncode != 0:
        # Failed to create pod -> treat as no certs
        # print for debug if needed:
        # print(proc.stderr.decode(), file=sys.stderr)
        return ""

    return pod_name


def json_to_yaml(obj: Any) -> str:
    """
    Very small JSON->YAML for our simple manifest, to avoid adding pyyaml.
    Good enough for this structure.
    """
    # we cheat: kubectl happily accepts JSON as YAML when passed with -f -.
    # So we just return JSON string.
    return json.dumps(obj)


def wait_for_pod_done(kubectl_cmd: List[str], scan_ns: str, pod_name: str, timeout_sec: int = 120) -> str:
    """
    Wait until pod phase is Succeeded or Failed, or timeout.
    Returns phase string (Succeeded/Failed/Unknown/Timeout)
    """
    start = time.time()
    while True:
        if time.time() - start > timeout_sec:
            return "Timeout"

        proc = run(kubectl_cmd + ["get", "pod", pod_name, "-n", scan_ns, "-o", "json"])
        if proc.returncode != 0:
            # Pod might not exist yet or already deleted
            time.sleep(2)
            continue

        data = json.loads(proc.stdout.decode() or "{}")
        phase = data.get("status", {}).get("phase", "Unknown")
        if phase in ("Succeeded", "Failed"):
            return phase

        time.sleep(2)


def get_pod_logs(kubectl_cmd: List[str], scan_ns: str, pod_name: str) -> str:
    proc = run(kubectl_cmd + ["logs", "-n", scan_ns, pod_name])
    if proc.returncode != 0:
        return ""
    return proc.stdout.decode()


def delete_pod(kubectl_cmd: List[str], scan_ns: str, pod_name: str) -> None:
    run(kubectl_cmd + ["delete", "pod", pod_name, "-n", scan_ns, "--ignore-not-found=true"])


def extract_certs_with_ephemeral_pod(
    kubectl_cmd: List[str],
    scan_ns: str,
    image: str,
    ca_paths: List[str],
) -> List[Dict[str, str]]:
    pod_name = create_scan_pod(kubectl_cmd, scan_ns, image, ca_paths)
    if not pod_name:
        return []

    try:
        phase = wait_for_pod_done(kubectl_cmd, scan_ns, pod_name)
        if phase != "Succeeded":
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
        delete_pod(kubectl_cmd, scan_ns, pod_name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract CA certificates from K8S images using ephemeral pods → JSON output",
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
        help="Namespace in which ephemeral scan pods will run (default: %(default)s)",
    )
    args = parser.parse_args()

    kubectl_cmd = args.kubectl
    ca_paths = CONFIG["ca_paths"]
    scan_ns = args.scan_namespace

    images_info = get_images_and_namespaces(kubectl_cmd)

    result = []
    for image, info in sorted(images_info.items(), key=lambda kv: kv[0]):
        ns_set = info["namespaces"]

        certs = extract_certs_with_ephemeral_pod(
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
