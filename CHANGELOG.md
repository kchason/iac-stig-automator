# Changelog

## 0.4.0

- Updated the bundled STIG checklist catalogs to current DISA releases: Kubernetes V2R6, Crunchy Data Postgres 16 V1R3, Oracle MySQL 8.0 V2R3, Azure SQL Database V2R4, Azure SQL Managed Instance V1R1.
- Added the `documentdb` module, which checks Amazon DocumentDB Terraform resources against the MongoDB Enterprise Advanced 8.x STIG V1R1 (55 controls) and writes `.cklb` checklists for it.
- The release workflow now also publishes `kchason/iac-stig-automator:<version>` and `:latest` multi-arch images (amd64 and arm64) to Docker Hub.
- Blank output filenames stay stable when CPython reuses resource ids.

## 0.3.0

First public release. Install with `pip install iac-stig-automator`. `stig-check` evaluates Terraform plan and state JSON against the bundled STIG modules and can write text, JSON, JUnit, and STIG Viewer `.cklb` output.
