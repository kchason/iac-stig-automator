FROM python:3.12-slim

LABEL org.opencontainers.image.title="STIG Automator"
LABEL org.opencontainers.image.description="Evaluate Terraform plan/state JSON against STIG controls"

WORKDIR /app

COPY pyproject.toml README.md LICENSE NOTICE DISCLAIMER.md ./
COPY src ./src

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade 'pip>=26.2' \
    && pip install --no-cache-dir . \
    && python -m pip uninstall -y pip \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin stig \
    && mkdir -p /work \
    && chown stig:stig /work

WORKDIR /work

USER stig

# One-shot CLI image; not a long-running service.
HEALTHCHECK NONE

ENTRYPOINT ["stig-check"]
CMD ["--help"]
