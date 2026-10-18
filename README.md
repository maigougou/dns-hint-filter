# DNS Hint Filter

English | [简体中文](README.zh-CN.md)

A small UDP DNS forwarder for Debian and Fedora that removes `ipv4hint` and
`ipv6hint` from HTTPS (type 65) resource records. Useful with Firefox configured
to use your system resolver.

```text
Firefox (DoH off) -> system resolver -> DNS Hint Filter -> upstream UDP DNS
                                       <- HTTPS records without IP hints
```

## Features

- IPv4 and IPv6 source CIDR allowlists, checked before forwarding.
- Removes hints from HTTPS records in all three DNS response sections.
- Preserves other parameters, including ALPN, ECH, port and unknown keys.
- Repairs `mandatory` lists after removing hints.
- Independent upstream sockets and randomized query IDs, response validation,
  deadlines and a shared concurrency limit.
- A hardened systemd unit and tests using a local mock upstream.

This is **UDP only**: it does not accept TCP queries or retry truncated upstream
responses over TCP. Rewritten HTTPS records cannot be validated by a downstream
DNSSEC validator. Read [limitations](#limitations) before changing system DNS.

## Install dependencies

Requires Python 3.9+ and dnspython >=2.6.1,<3.

```bash
git clone https://github.com/maigougou/dns-hint-filter.git
cd dns-hint-filter
```

On **Debian 13**:

```bash
sudo apt update
sudo apt install python3 python3-dnspython bind9-dnsutils
```

On **Fedora**:

```bash
sudo dnf install python3 python3-dns bind-utils
```

Some Fedora releases call the dependency `python3-dnspython` instead.

On **Debian 12**, the distribution's dnspython 2.3.0 is below the required
version. Install dependencies in a virtual environment:

```bash
sudo apt update
sudo apt install python3 python3-venv bind9-dnsutils
sudo python3 -m venv /opt/dns-hint-filter/venv
sudo /opt/dns-hint-filter/venv/bin/python -m pip install -r requirements.txt
```

For this installation, replace `python3` in the commands below with
`/opt/dns-hint-filter/venv/bin/python`. This approach also works on Debian 13.

## Try it without changing system DNS

```bash
cp config.example.json config.json
python3 dns_hint_filter.py --config config.json --check-config
python3 dns_hint_filter.py --config config.json --verbose
```

The sample listens on `127.0.0.1:5300` and `[::1]:5300`, allows only loopback
clients and forwards to `1.1.1.1:53`. Edit the JSON to choose your upstream.

In another terminal:

```bash
dig @1.1.1.1 cloudflare.com TYPE65 +ignore
dig @127.0.0.1 -p 5300 cloudflare.com TYPE65 +ignore
dig @127.0.0.1 -p 5300 example.com A +ignore
```

If the upstream HTTPS answer includes hints, the filtered answer should omit
them while keeping the other parameters. A domain without hints cannot
demonstrate filtering; the tests supply deterministic records. `+ignore`
prevents dig from retrying truncated answers over TCP.

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `["127.0.0.1"]` | Local IP addresses to bind; sample also includes `::1` |
| `port` | `53` | Listening UDP port; sample uses `5300` |
| `allow` | `["127.0.0.0/8", "::1/128"]` | Allowed source networks in canonical CIDR notation |
| `upstream` | Required | Upstream IP literal, never a hostname |
| `upstream_port` | `53` | Upstream UDP port |
| `timeout` | `3.0` | Total upstream request deadline in seconds |
| `max_inflight` | `256` | Maximum concurrent requests across all listeners |

Use unbracketed IPv6 literals in JSON. An upstream must not resolve back through
this service, including indirect loops through your system stub resolver.
Restart the service after editing its configuration.

## Run as a systemd service

Stop the foreground instance and set `port` to **53** in `config.json` before
using it as a system DNS server. Check for conflicts:

```bash
sudo ss -lunp 'sport = :53'
```

A resolver bound only to `127.0.0.53:53` can coexist with this service on
`127.0.0.1:53`. A wildcard listener on port 53 may conflict.

If using the virtual environment, first change the supplied service's
`ExecStart` line to:

```ini
ExecStart=/opt/dns-hint-filter/venv/bin/python /usr/local/lib/dns-hint-filter/dns_hint_filter.py --config /etc/dns-hint-filter.json
```

Keep the virtual environment outside home directories: `ProtectHome=yes`
prevents the service from accessing them.

```bash
sudo install -d -m 0755 /usr/local/lib/dns-hint-filter
sudo install -m 0644 dns_hint_filter.py /usr/local/lib/dns-hint-filter/dns_hint_filter.py
sudo install -m 0644 config.json /etc/dns-hint-filter.json
sudo install -m 0644 dns-hint-filter.service /etc/systemd/system/dns-hint-filter.service
if command -v restorecon >/dev/null 2>&1; then
  sudo restorecon -RF /usr/local/lib/dns-hint-filter /etc/dns-hint-filter.json /etc/systemd/system/dns-hint-filter.service
fi
sudo systemctl daemon-reload
sudo systemctl enable --now dns-hint-filter
sudo systemctl status dns-hint-filter --no-pager
dig @127.0.0.1 cloudflare.com TYPE65 +ignore
```

Logs: `journalctl -u dns-hint-filter -f`. The service uses a dynamic non-root
user with the capability needed to bind privileged ports.

## Firefox and system DNS

1. Turn Firefox DNS over HTTPS **Off**, or set `network.trr.mode` to `5`.
2. Set your connection's DNS server to `127.0.0.1` using the network manager
   actually installed on the machine. Disable automatic DNS from DHCP/IPv6 RA
   for that connection, and check VPN or fallback DNS settings for bypasses.
3. Clear Firefox's DNS cache at `about:networking#dns`. If using
   systemd-resolved, also run `sudo resolvectl flush-caches`.

System DNS changes affect other applications. Not every Debian installation
uses NetworkManager or systemd-resolved; do not overwrite a managed
`/etc/resolv.conf`. See the [Chinese guide](README.zh-CN.md) for NetworkManager
examples and rollback steps. Save existing DNS settings before changing them.

For LAN use, add the server's LAN IP to `listen`, add trusted networks to
`allow`, and permit those sources to reach UDP 53 through your existing
firewall. Point clients at the server's LAN address. The allowlist sees the
post-NAT source address and is not authentication.

## Limitations

- **UDP only.** Truncated responses retain TC. Responses are bounded by the
  client's UDP size, with an EDNS cap of 1232 bytes or 512 without EDNS. Queries
  requiring TCP for a complete answer cannot be completed by this forwarder.
- **DNSSEC rewriting.** When an HTTPS RRset changes, its signatures are removed
  and AD is cleared. Unrelated signatures remain. The forwarder does not
  validate DNSSEC; place any validating upstream before the filter. A validating
  downstream cannot authenticate modified records; clearing AD does not fix this.
- **Ordinary single-question queries only.** No UPDATE, zone transfers,
  TSIG/SIG(0) proxying, caching or upstream failover.
- **Overload and invalid requests.** Disallowed, malformed and excess requests
  are dropped. Upstream timeout/failure produces SERVFAIL.
- **Scope.** A/AAAA and SVCB (type 64) record contents are not rewritten. Removing
  hints does not disable IPv6 or force Firefox to issue HTTPS queries.

## Development and validation

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Tests use temporary loopback UDP sockets and do not query public DNS. CI covers
multiple Python versions and Debian/Fedora containers; see Actions for current
results. Real-host systemd startup, firewall integration and Firefox behavior
still need validation on your deployment machine.

## References

- [RFC 9460: HTTPS/SVCB records](https://www.rfc-editor.org/rfc/rfc9460.html)
- [Firefox DoH settings](https://support.mozilla.org/en-US/kb/dns-over-https)
- [Debian 12 dnspython](https://packages.debian.org/bookworm/python3-dnspython)
- [Debian 13 dnspython](https://packages.debian.org/trixie/python3-dnspython)
