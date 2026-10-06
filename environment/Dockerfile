# syntax=docker/dockerfile:1
# The platform manifest (not the multi-platform index) is pinned deliberately.
FROM python:3.10.20-slim-bookworm@sha256:6dafe336b64dbf76f7ec872d07e58b5c7de0e2ea5d4c0853a05c3b6be3278b00

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=UTC

COPY environment/wheelhouse/ /opt/mvscan/wheelhouse/
COPY environment/python.lock /opt/mvscan/python.lock
RUN python -m pip install \
      --no-index \
      --find-links=/opt/mvscan/wheelhouse \
      --require-hashes \
      --no-deps \
      -r /opt/mvscan/python.lock \
    && rm -rf /opt/mvscan/wheelhouse

COPY --chmod=0755 environment/toolchains/foundry-v1.5.1/forge /usr/local/bin/forge
COPY --chmod=0755 environment/toolchains/foundry-v1.5.1/cast /usr/local/bin/cast
COPY --chmod=0755 environment/toolchains/foundry-v1.5.1/anvil /usr/local/bin/anvil
COPY --chmod=0755 environment/toolchains/foundry-v1.5.1/chisel /usr/local/bin/chisel

COPY environment/toolchains/solc/ /opt/mvscan/solc/
COPY environment/toolchains/node/ /opt/mvscan/node/
COPY environment/toolchains/yarn/ /opt/mvscan/yarn/

WORKDIR /workspace
