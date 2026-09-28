# Changelog

## 2.2.4

- Added the last successful scan timestamp to the Grafana dashboard.
- Added `subssl update` to download and reinstall the latest Debian release.
- Restricted direct pushes to `main` to the repository owner.

## 2.2.3

- Grafana: table displays the precise TLS probe error and no longer shows hostname-mismatch status.

## 2.2.2

- Grafana: table now ranks certificate/TLS/hostname problems above healthy hosts.

## 2.2.1

- Display certificate start/end dates as `DD.MM.YYYY`.
- Added Prometheus warning and critical certificate-expiry alert rules.

## 2.2.0

- Scan only the zone apex and direct, non-service subdomains; skip ACME/DKIM-style and multi-label DNS records.
- Added actual certificate type/issuer details to the Grafana table and hid Pushgateway service labels.

## 2.1.4

- Fixed Debian launcher working directory so it imports the packaged `subssl` module.

## 2.1.3

- Remove recognised legacy user-install launchers so Debian installs cannot be shadowed by `~/.local/bin`.

## 2.1.2

- Remove the recognised legacy manual-install launcher so `/usr/bin/subssl` from the Debian package is used.

## 2.1.1

- Added a Grafana table metric with certificate presence, start/end dates and endpoint.
- Removed the certificate lifetime chart and redesigned the certificate table.

## 2.1.0

- Modernized and grouped the terminal GUI navigation.
- Added configurable Prometheus Pushgateway publishing after every scan.
- Added hostname/domain/IP/port labels and certificate-health metrics.
- Added importable Grafana SSL certificate dashboard.
- Added Debian package build script and package metadata.

## 2.0.1

- Fixed `sudo bash install.sh`: system installs now go to `/opt/subssl` with launcher `/usr/local/bin/subssl`.
- System install no longer depends on root's `$HOME` or `/root/.local/bin`.
- Installer removes the broken v2.0.0 root-local runtime during upgrade.
- No shell profile edits are required for a normal sudo/system installation.
- Added explicit warning not to `source ~/.bashrc` from zsh/fish/etc.

## 2.0.0

- NIC.RU DNS zone is the source of truth for hostnames.
- Local DNS first, Cloudflare/Google only as fallback.
- TUI configuration and scheduling.
