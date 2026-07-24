ARG branch=stable
ARG base=cccs/assemblyline-v4-service-base

FROM ghcr.io/astral-sh/uv:0.11.29 AS uv

# Builder: build the service wheel
FROM python:3.11-slim AS builder
COPY --from=uv /uv /bin/uv
ENV UV_PYTHON_DOWNLOADS=0
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv build --wheel -o dist/

# AL4 service base
FROM $base:$branch

ENV SERVICE_PATH=triage_sandbox.service.TriageSandbox

USER assemblyline

WORKDIR /opt/al_service

COPY --chown=assemblyline:assemblyline requirements.txt ./
COPY --chown=assemblyline:assemblyline --from=builder /app/dist/*.whl ./
RUN pip install --no-cache-dir --user --no-deps -r requirements.txt && \
    pip install --no-cache-dir --user --no-deps *.whl

COPY service_manifest.yml ./

# Patch version in manifest
ARG version=0.0.0.dev0
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
