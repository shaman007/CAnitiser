#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

CONFIG = {
    "kubectl_cmd": ["kubectl"],
    "runtime_cmd": ["docker"],
    "ca_paths": [
        "/etc/ssl/certs",
        "/etc/pki",
        "/usr/local/share/ca-certificates",
        "/usr/share/ca-certificates/mozilla",
    ],
}


def run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


# -------------------------------------------------
# K8S IMAGE DISCOVERY (image → namespaces)
# -------------------------------------------------
def get_images_per_namespace(kubectl_cmd: List[str]) -> Dict[str, Set[str]]:
    """
    returns:
       {
         "imagename:tag": {"ns1", "ns2"},
         ...
       }
    """
    cmd = kubectl_cmd + ["get", "pods", "-A", "-o", "json"]
    proc = run(cmd)
    if proc.returncode != 0:
        print(proc.stderr.decode(), file=sys.stderr)
        sys.exit(1)

    data = json.loads(proc.stdout.decode() or "{}")
    images: Dict[str, Set[str]] = defaultdict(set)

    for item in data.get("items", []):
        ns = item["metadata"]["namespace"]
        spec = item.get("spec", {})

        for c in spec.get("containers", []):
            if c.get("image"):
                images[c["image"]].add(ns)

        for c in spec.get("initContainers", []):
            if c.get("image"):
                images[c["image"]].add(ns)

        for c in spec.get("ephemeralContainers", []):
            if c.get("image"):
                images[c["image"]].add(ns)

    return images


# -------------------------------------------------
# DOCKER / NERDCTL HELPERS
# -------------------------------------------------
def pull_image(runtime_cmd: List[str], image: str) -> bool:
    proc = run(runtime_cmd + ["pull", image])
    return proc.returncode == 0


def extract_certs(runtime_cmd: List[str], image: str, ca_paths: List[str]) -> List[Dict]:
    """
    returns list of:
       [{"path": "...", "subject": "..."}]
    """
    ca_paths_arg = " ".join(ca_paths)

    script = f"""#!/bin/sh
set -e

for base in {ca_paths_arg}; do
  if [ -d "$base" ]; then
    find "$base" -type f 2>/dev/null | while read f; do
      # Fast skip: no PEM blocks
      grep -q "BEGIN CERTIFICATE" "$f" 2>/dev/null || continue

      tmpdir="$(mktemp -d /tmp/cacerts.XXXXXX 2>/dev/null || mktemp -d)"

      awk '
        /-----BEGIN CERTIFICATE-----/ {{
          in_cert = 1
          idx++
          fn = sprintf("%s/cert-%04d.pem", d, idx)
          print > fn
          next
        }}
        /-----END CERTIFICATE-----/ {{
          if (in_cert) {{
            print >> fn
            close(fn)
            in_cert = 0
          }}
          next
        }}
        {{
          if (in_cert) {{
            print >> fn
          }}
        }}
      ' d="$tmpdir" "$f"

      for pem in "$tmpdir"/cert-*.pem; do
        [ -f "$pem" ] || continue
        sub="$(openssl x509 -in "$pem" -noout -subject 2>/dev/null || true)"
        if [ -n "$sub" ]; then
          printf '%s\\t%s\\n' "$f" "$sub"
        fi
      done

      rm -rf "$tmpdir"
    done
  fi
done
"""

    cmd = runtime_cmd + [
        "run",
        "--rm",
        "--pull=never",
        "--entrypoint=/bin/sh",
        image,
        "-c",
        script,
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=40,
        )
    except subprocess.TimeoutExpired:
        return []

    if proc.returncode != 0:
        return []

    certs = []
    for line in proc.stdout.decode().splitlines():
        if "\t" not in line:
            continue
        path, subject = line.split("\t", 1)
        certs.append({"path": path, "subject": subject})
    return certs


# -------------------------------------------------
# MAIN
# -------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Extract CA certificates from K8S images → JSON output")
    parser.add_argument("--kubectl", nargs="+", default=CONFIG["kubectl_cmd"])
    parser.add_argument("--runtime", nargs="+", default=CONFIG["runtime_cmd"])
    args = parser.parse_args()

    kubectl_cmd = args.kubectl
    runtime_cmd = args.runtime
    ca_paths = CONFIG["ca_paths"]

    # Get: image → namespaces
    images_map = get_images_per_namespace(kubectl_cmd)

    result = []

    for image, namespaces in images_map.items():
        pull_ok = pull_image(runtime_cmd, image)
        cert_list = []

        if pull_ok:
            cert_list = extract_certs(runtime_cmd, image, ca_paths)

        result.append({
            "image": image,
            "namespaces": sorted(list(namespaces)),
            "certs": cert_list,   # always include, even if empty
        })

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

