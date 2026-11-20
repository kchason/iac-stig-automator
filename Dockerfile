# syntax=docker/dockerfile:1

FROM python:3.15-alpine AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE NOTICE DISCLAIMER.md ./
COPY src ./src

RUN pip install --no-cache-dir --target /install . \
    && mkdir /work

FROM python:3.15-alpine

LABEL org.opencontainers.image.title="STIG Automator"
LABEL org.opencontainers.image.description="Evaluate Terraform plan/state JSON against STIG controls"

COPY --from=builder /install /app
COPY --from=builder --chown=1000:1000 /work /work

RUN apk upgrade --no-cache \
    && python -m pip uninstall -y pip setuptools wheel 2>/dev/null; \
    adduser -D -u 1000 -s /sbin/nologin stig

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /work

USER stig

# One-shot CLI image; not a long-running service.
HEALTHCHECK NONE

ENTRYPOINT ["python", "-m", "stig_automator.cli"]
CMD ["--help"]
