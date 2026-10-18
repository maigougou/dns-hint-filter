# Changelog

## 0.1.0

Initial release:

- UDP DNS forwarding with IPv4/IPv6 source CIDR allowlists.
- HTTPS address-hint removal, mandatory-list repair and DNSSEC metadata handling.
- Request deadlines, response validation and bounded concurrency.
- Debian 12/13 and Fedora installation documentation in English and Chinese.
- systemd service and automated protocol/integration tests.

Known limits: UDP only; no downstream DNSSEC validation of rewritten records;
no cache or upstream failover. Host-level service and Firefox integration must
be verified on the deployment machine.
