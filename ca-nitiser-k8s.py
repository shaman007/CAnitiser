#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from collections import defaultdict
from typing import Dict, List, Tuple, Any


CONFIG = {
    "kubectl_cmd": ["kubectl"],
    "ca_paths": [
        "/etc/ssl/certs",
        "/etc/pki",
        "/usr/local/share/ca-certificates",
    ],
}


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def get_images_and_pods(kubectl_cmd: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Returns mapping:
      image -> {
        "namespaces": set([...]),
        "example": (namespace, pod_name, container_name)
      }
    """
    cmd = kubectl_cmd + ["get", "pods", "-A", "-o", "json"]
    proc = run(cmd)
    if proc.returncode != 0:
        print("ERROR: kubectl get pods failed:", proc.stderr.decode(), file=sys.stderr)
        sys.exit(1)

    data = json.loads(proc.stdout.decode() or "{}")
    images: Dict[str, Dict[str, Any]] = {}

    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        ns = meta.get("namespace", "default")
        pod_name = meta.get("name", "")

        def handle_containers(container_list_key: str):
            for c in spec.get(container_list_key, []) or []:
                image = c.get("image")
                cname = c.get("name", "container")
                if not image:
                    continue
                if image not in images:
                    images[image] = {
                        "namespaces": set(),
                        "example": (ns, pod_name, cname),
                    }
                images[image]["namespaces"].add(ns)

        handle_containers("containers")
        handle_containers("initContainers")
        handle_containers("ephemeralContainers")

    return images


def extract_certs_via_exec(
    kubectl_cmd: List[str],
    namespace: str,
    pod: str,
    container: str,
    ca_paths: List[str],
) -> List[Dict[str, str]]:
    """
    Run openssl in a real pod/container that uses the image.

    Returns list of {path, subject}.
    """
    ca_paths_arg = " ".join(ca_paths)

    script = f"""
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

    cmd = kubectl_cmd + [
        "exec",
        "-n",
        namespace,
        pod,
        "-c",
        container,
        "--",
        "sh",
        "-c",
        script,
    ]

    proc = run(cmd)
    if proc.returncode != 0:
        # pod may not have sh/openssl/etc.
        return []

    certs: List[Dict[str, str]] = []
    for line in proc.stdout.decode().splitlines():
        if "\t" not in line:
            continue
        path, subject = line.split("\t", 1)
        certs.append({"path": path, "subject": subject})
    return certs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract CA certificates from K8S images via kubectl exec → JSON output",
    )
    parser.add_argument(
        "--kubectl",
        nargs="+",
        default=CONFIG["kubectl_cmd"],
        help="kubectl command (default: %(default)s)",
    )
    args = parser.parse_args()

    kubectl_cmd = args.kubectl
    ca_paths = CONFIG["ca_paths"]

    images_info = get_images_and_pods(kubectl_cmd)

    result = []
    for image, info in sorted(images_info.items(), key=lambda kv: kv[0]):
        ns_set = info["namespaces"]
        example_ns, example_pod, example_container = info["example"]

        certs = extract_certs_via_exec(
            kubectl_cmd,
            example_ns,
            example_pod,
            example_container,
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
