# CA Image Scanner for Kubernetes

This project provides a complete workflow for extracting, analyzing, and reporting CA certificates found inside container images running in a Kubernetes cluster. It is designed for clusters where CA trust hygiene, internal CA usage, or detection of unwanted roots is required.

The system operates without Docker on nodes, relies fully on Kubernetes APIs, and uses OCI-compliant scanning via skopeo and umoci.

## Overview

### 1. Image Scanner (Job-Based)

A Python scanner (`ca-nitiser-k8s.py`) discovers all container images in a namespace or the entire cluster.  
For each image, it creates a dedicated scan Job. Each job:

- pulls the image via skopeo as OCI
- unpacks it with umoci (rootless)
- searches for certificate files
- extracts certificate subjects using openssl
- prints results in TSV format

The controller collects these results into `images.json`.

### 2. CA Classification

`ca-analyse.py` reads `images.json` and applies a policy describing:

- whitelist substrings
- blacklist substrings

Each certificate receives a classification:

- GREEN — matched whitelist  
- RED — matched blacklist  
- NOT_MATCHED — neither matched

Each image receives a final status:

- RED — at least one red certificate  
- YELLOW — certificates present and at least one not matched  
- GREEN — no certificates or all green

The output is `report.json`.

### 3. CaImageReport CRD

Scan results are stored in Kubernetes as `CaImageReport` custom resources.

apiVersion: security.andreybondarenko.com/v1alpha1
kind: CaImageReport
spec:
scanRef:
name: ...
namespace: ...
summary:
totalImages:
green:
yellow:
red:
report:
- image: ...
namespaces: [...]
status: GREEN|YELLOW|RED
certs:
- path: ...
subject: ...
classification: ...


### 4. Report Publisher

`push-report.py` creates or updates `CaImageReport` objects, requiring RBAC permissions for:

apiGroups: ["security.andreybondarenko.com"]
resources: ["caimagereports"]
verbs: ["get", "list", "create", "patch"]


### 5. HTML UI Server

`ca-report-server.py` serves an HTML interface:

- index listing all CaImageReport objects
- per-report pages with summaries, images, certificate details, and classifications

Runs as a Deployment with optional Ingress.

## Workflow Summary

ca-nitiser-k8s.py → spawn scan jobs
scan jobs → extract certs → collected into images.json
ca-analyse.py → classify certs → produce report.json
push-report.py → create/update CaImageReport


## Key Dependencies

- Python 3.12
- Kubernetes Python client
- skopeo
- umoci
- openssl

## Docker Image

The `canitiser` image contains:

- ca-nitiser-k8s.py
- ca-analyse.py
- push-report.py
- ca-report-server.py
- required CLI tools and libraries

Example build:

docker buildx build
--platform linux/amd64,linux/arm64
-t harbor.andreybondarenko.com/library/canitiser:latest
--push .


## Running the Scanner

# Example Job for namespace scan

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: ca-scan-mail
  namespace: ca-scanner
spec:
  template:
    spec:
      serviceAccountName: ca-scanner
      containers:
        - name: scanner
          image: harbor.andreybondarenko.com/library/canitiser:latest
          command: ["python", "/app/ca-nitiser-k8s.py"]
          args:
            - --scan-namespace
            - mail
            - --report-name
            - ca-scan-mail-report
      restartPolicy: Never
```

## Running the HTML UI

# Deployment

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ca-report-ui
  namespace: ca-scanner
spec:
  replicas: 1
  template:
    metadata:
      labels: { app: ca-report-ui }
    spec:
      serviceAccountName: ca-scanner
      containers:
        - name: ui
          image: harbor.andreybondarenko.com/library/canitiser:latest
          command: ["python", "/app/ca-report-server.py"]
          env:
            - name: REPORT_NAMESPACE
              value: "ca-scanner"
          ports:
            - containerPort: 8080
```
# Ingress Example
```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ca-report-ui
  namespace: ca-scanner
  annotations:
    kubernetes.io/ingress.class: "traefik"
spec:
  rules:
    - host: ca-report.w386.k8s.my.lan
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: ca-report-ui
                port:
                  number: 80
```
### Non Kubernetes use

## Scanner

Since we are not in the K8S, we can use kubectl and local authenticaton. The test.sh script does the scan of the
cluster, generates .json and fancy .html reports.

### Future Extensions

    CaImageScan CRD for declarative scan requests

    periodic scanning via CronJob

    operator-driven scanning

    enforcement for blocked certificates

    multi-policy support