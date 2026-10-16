#!/usr/bin/env bash
# Smoke-test a built service image: installed dependencies are consistent,
# the service class loads from SERVICE_PATH, and the manifest carries the
# expected version.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <image> <expected-version>" >&2
  exit 2
fi

image="$1"
expected_version="$2"

docker run --rm -i \
  --entrypoint python \
  --env EXPECTED_VERSION="$expected_version" \
  "$image" - <<'PY'
import importlib
import os
import subprocess
import sys

import yaml
from assemblyline_v4_service.common.base import ServiceBase

subprocess.run([sys.executable, "-m", "pip", "check"], check=True)

module_name, class_name = os.environ["SERVICE_PATH"].rsplit(".", 1)
service_class = getattr(importlib.import_module(module_name), class_name)
if not issubclass(service_class, ServiceBase):
    sys.exit(f"{service_class!r} is not a ServiceBase subclass")

with open("service_manifest.yml", encoding="utf-8") as manifest_file:
    manifest = yaml.safe_load(manifest_file)

expected_version = os.environ["EXPECTED_VERSION"]
if manifest["version"] != expected_version:
    sys.exit(f"Manifest version {manifest['version']!r} does not match {expected_version!r}")

service_class()
print(f"Smoke test passed: {manifest['name']} {manifest['version']}")
PY
