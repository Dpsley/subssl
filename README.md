# subssl

`subssl` is a self-hosted TLS certificate inventory and monitoring tool for a
DNS zone hosted at NIC.RU. It reads the names in a zone, resolves each enabled
hostname, opens a TLS connection, and records certificate and connection
health. It is intended for administrators who want a repeatable inventory of
their externally and internally reachable HTTPS endpoints.

The tool deliberately does not discover arbitrary subdomains. The DNS zone is
the source of truth. DNS queries use the configured local resolvers first; the
public fallback resolvers (`1.1.1.1` and `8.8.8.8`) are used only when none of
the local resolvers returns a record.

## What it does

- Imports the apex and direct, non-service hostnames from a NIC.RU DNS zone.
- Checks TLS endpoints on configurable ports and records expiry, issuer,
  hostname matching, and connection failures.
- Writes JSON and CSV reports locally.
- Provides a terminal UI for configuration, hostname selection, and scheduled
  scans.
- Can publish metrics to a Prometheus Pushgateway. A Grafana dashboard and
  Prometheus alert rules are included.

## Requirements

- Python 3.10 or newer.
- A NIC.RU OAuth application and a NIC.RU account with read access to the DNS
  zone.
- On Debian or Ubuntu, `python3-venv` for the installer. Building a `.deb`
  additionally requires `dpkg-deb`.

## Install from source

Clone the repository and run the installer:

```bash
git clone https://github.com/Dpsley/subssl.git
cd subssl
chmod +x install.sh
sudo ./install.sh
```

This installs the application under `/opt/subssl` and the `subssl` command
under `/usr/local/bin`. It does not modify a shell profile.

For a per-user installation, run the same command without `sudo`:

```bash
./install.sh
```

The command is installed in `~/.local/bin`. If that directory is not already
on your `PATH`, add it to the startup file for the shell you actually use, then
open a new shell:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### Install with pip

For development or a virtual-environment installation:

```bash
git clone https://github.com/Dpsley/subssl.git
cd subssl
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
subssl
```

### Debian package

Build the package from a checkout, then install the generated file:

```bash
./build-deb.sh
sudo apt install ./dist/subssl_2.2.3_all.deb
```

Every commit pushed to `main` also creates a GitHub Release with the generated
Debian package attached.

## First run

Launch the terminal UI:

```bash
subssl
```

In **NIC.RU / DNS zone settings**, provide the zone name, NIC.RU OAuth
application credentials, and NIC.RU account credentials. The application uses
a read-only DNS scope (`GET:/dns-master/.+`) and stores the refresh token for
future runs.

Credentials are stored only on the machine running `subssl` in
`~/.config/subssl/secrets.json` with `0600` permissions. The repository does
not contain credentials, zone data, scan reports, or build artifacts.

Use **Hostnames** to choose which names are scanned, and **Local DNS settings**
to add the resolvers appropriate for your network.

## Commands

```bash
# Open the configuration UI
subssl

# Run a scan using saved settings
subssl scan -v

# Show configuration status without printing secrets
subssl status
```

Reports are written to `~/.local/state/subssl/reports/` by default.

## Monitoring

Set a Prometheus Pushgateway URL in **Automation & monitoring → Prometheus /
Grafana delivery**. After each scan, `subssl` publishes a complete TLS metrics
snapshot. Configure Prometheus to scrape the Pushgateway, then import
[`grafana/subssl-certificates-dashboard.json`](grafana/subssl-certificates-dashboard.json).

The alert rules in
[`prometheus/subssl-alerts.yml`](prometheus/subssl-alerts.yml) define warning
and critical alerts for certificates approaching or past expiry.

## Security and privacy

Treat the local configuration directory and report directory as sensitive: they
may contain account credentials, internal hostnames, addresses, and endpoint
metadata. They are excluded by `.gitignore`. Review any generated report before
sharing it.

## License

No open-source license has been granted for this repository. Contact the
copyright holder for permission to use, copy, modify, or distribute the code.
