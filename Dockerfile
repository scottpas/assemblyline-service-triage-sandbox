ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base

# Builder: use uv to export pinned requirements from uv.lock
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv
ENV UV_PYTHON_DOWNLOADS=0
WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv export --frozen --no-dev --no-emit-project -o requirements.txt

# AL4 service base
FROM $base:$branch

ENV SERVICE_PATH=service.TriageSandbox

USER root

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

USER assemblyline

WORKDIR /opt/al_service

COPY --from=builder /app/requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

COPY src/ ./
COPY service_manifest.yml ./

# Patch version in manifest
ARG version=4.4.1.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

USER assemblyline
