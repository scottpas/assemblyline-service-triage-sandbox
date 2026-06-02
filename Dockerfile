ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base
FROM $base:$branch

ENV SERVICE_PATH service.TriageSandbox

USER root

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

USER assemblyline

WORKDIR /opt/al_service

COPY pyproject.toml ./
RUN pip install --no-cache-dir --user . && rm -rf ~/.cache/pip

COPY src/ ./
COPY service_manifest.yml ./

# Patch version in manifest
ARG version=4.4.1.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
