ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base

# Builder: export pinned requirements and build the service wheel
FROM python:3.14-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /bin/uv
ENV UV_PYTHON_DOWNLOADS=0
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv export --frozen --no-dev --no-emit-project -o requirements.txt && \
    uv build --wheel -o dist/

# AL4 service base
FROM $base:$branch

ENV SERVICE_PATH=triage_sandbox.service.TriageSandbox

USER root

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

USER assemblyline

WORKDIR /opt/al_service

COPY --chown=assemblyline:assemblyline --from=builder /app/requirements.txt ./
COPY --chown=assemblyline:assemblyline --from=builder /app/dist/*.whl ./
RUN pip install --no-cache-dir --user -r requirements.txt && \
    pip install --no-cache-dir --user --no-deps *.whl

COPY service_manifest.yml ./

# Patch version in manifest
ARG version=4.4.1.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
