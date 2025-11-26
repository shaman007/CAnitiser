# Minimal Python base
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps: curl + ca-certificates (for kubectl download, HTTPS)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# --- kubectl CLI (in-cluster auth or external kubeconfig) ---
ARG KUBECTL_VERSION=latest
RUN set -eux; \
    if [ "$KUBECTL_VERSION" = "latest" ]; then \
      KVER="$(curl -L -s https://dl.k8s.io/release/stable.txt)"; \
    else \
      KVER="v${KUBECTL_VERSION}"; \
    fi; \
    curl -L "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl && \
    chmod +x /usr/local/bin/kubectl

# If you ever decide to use extra Python libs, add a requirements.txt and uncomment:
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner/analyzer/report generator scripts
COPY ca-nitiser-k8s.py ca-analyse.py ca-report-html.py push-report.py ./ 

# Non-root user
RUN useradd -r -u 10001 -g users scanner && \
    chown -R scanner:users /app
USER scanner

# Default command: just show help.
# Jobs/cronjobs will override this with the full pipeline, e.g.:
#   python ca-nitiser.py > /work/images.json && \
#   python ca-analyse.py --images /work/images.json --policy /policy/policy.json > /work/report.json && \
#   python ca-report-html.py --report /work/report.json -o /work/report.html
ENTRYPOINT ["python"]
CMD ["ca-nitiser.py", "--help"]
