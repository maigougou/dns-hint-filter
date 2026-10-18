#!/usr/bin/env python3
"""UDP DNS forwarder removing address hints from HTTPS (type 65) records."""

import argparse
import asyncio
import copy
import ipaddress
import json
import logging
import math
import secrets
import signal
import socket
from dataclasses import dataclass
from pathlib import Path

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdatatype
import dns.rrset
from dns.rdtypes.svcbbase import MandatoryParam, ParamKey

LOG = logging.getLogger("dns-hint-filter")
HINTS = frozenset((ParamKey.IPV4HINT, ParamKey.IPV6HINT))


@dataclass(frozen=True)
class Config:
    listen: tuple
    port: int
    allowed_networks: tuple
    upstream: str
    upstream_port: int
    timeout: float
    max_inflight: int

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        keys = {"listen", "port", "allow", "upstream", "upstream_port",
                "timeout", "max_inflight"}
        if not isinstance(data, dict) or set(data) - keys:
            raise ValueError("configuration must be an object containing only supported keys")
        listeners = data.get("listen", ["127.0.0.1"])
        allow = data.get("allow", ["127.0.0.0/8", "::1/128"])
        for key, values in (("listen", listeners), ("allow", allow)):
            if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
                raise ValueError(f"{key} must be a nonempty list of strings")
        listeners = tuple(str(ipaddress.ip_address(v)) for v in listeners)
        networks = tuple(ipaddress.ip_network(v, strict=True) for v in allow)
        upstream = str(ipaddress.ip_address(data["upstream"]))
        if ipaddress.ip_address(upstream).is_unspecified or ipaddress.ip_address(upstream).is_multicast:
            raise ValueError("upstream must be a unicast IP address")
        integers = {}
        for key, default, maximum in (("port", 53, 65535), ("upstream_port", 53, 65535),
                                       ("max_inflight", 256, 65535)):
            value = data.get(key, default)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{key} must be an integer from 1 to {maximum}")
            integers[key] = value
        timeout = data.get("timeout", 3.0)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if integers["port"] == integers["upstream_port"]:
            address = ipaddress.ip_address(upstream)
            for listener in map(ipaddress.ip_address, listeners):
                if listener == address or (listener.is_unspecified and address.is_loopback
                                           and listener.version == address.version):
                    raise ValueError("upstream may point back to this listener; use a different address or port")
        return cls(listeners, integers["port"], networks, upstream,
                   integers["upstream_port"], timeout, integers["max_inflight"])

    def allows(self, address):
        address = ipaddress.ip_address(address)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return any(address in network for network in self.allowed_networks)


def strip_hints(response):
    """Rewrite all HTTPS RRsets, preserving other parameters and unrelated RRs."""
    changed = set()
    sections = (response.answer, response.authority, response.additional)
    for section in sections:
        for index, rrset in enumerate(section):
            if rrset.rdtype != dns.rdatatype.HTTPS:
                continue
            replacement = dns.rrset.RRset(rrset.name, rrset.rdclass, rrset.rdtype)
            dirty = False
            for record in rrset:
                params = dict(record.params)
                if HINTS.intersection(params):
                    dirty = True
                    for key in HINTS:
                        params.pop(key, None)
                    mandatory = params.get(ParamKey.MANDATORY)
                    if mandatory is not None:
                        keys = [key for key in mandatory.keys if key not in HINTS]
                        if keys:
                            params[ParamKey.MANDATORY] = MandatoryParam(keys)
                        else:
                            params.pop(ParamKey.MANDATORY)
                    record = record.replace(params=params)
                replacement.add(record, rrset.ttl)
            if dirty:
                section[index] = replacement
                changed.add((rrset.name, rrset.rdclass))
    if changed:
        response.flags &= ~dns.flags.AD
        for section in sections:
            section[:] = [rrset for rrset in section if not (
                rrset.rdtype == dns.rdatatype.RRSIG
                and rrset.covers == dns.rdatatype.HTTPS
                and (rrset.name, rrset.rdclass) in changed)]
    return bool(changed)


async def exchange_udp(query, config):
    """Use one connected socket per query; keep queued datagrams when ignoring junk."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ipaddress.ip_address(config.upstream).version == 6 else socket.AF_INET

    async def exchange():
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            # A connected UDP socket accepts datagrams only from this peer.
            await loop.sock_connect(sock, (config.upstream, config.upstream_port))
            await loop.sock_sendall(sock, query.to_wire())
            while True:
                wire = await loop.sock_recv(sock, 65535)
                try:
                    reply = dns.message.from_wire(wire)
                except (dns.exception.DNSException, ValueError):
                    continue
                if query.is_response(reply):
                    return reply

    return await asyncio.wait_for(exchange(), timeout=config.timeout)


class Forwarder:
    """Shared concurrency budget across every listening socket."""

    def __init__(self, config):
        self.config = config
        self.tasks = set()

    def receive(self, data, address, transport):
        # Drop disallowed packets before parsing or creating upstream work.
        if not self.config.allows(address[0]) or len(self.tasks) >= self.config.max_inflight:
            return
        try:
            query = dns.message.from_wire(data)
        except (dns.exception.DNSException, ValueError):
            return
        if query.flags & dns.flags.QR or len(query.question) != 1:
            return
        if query.opcode() != dns.opcode.QUERY or query.question[0].rdtype in (
            dns.rdatatype.AXFR, dns.rdatatype.IXFR):
            self.error(query, address, transport, dns.rcode.NOTIMP)
            return
        # This is a query forwarder, not an UPDATE or signed-message proxy.
        if query.answer or query.authority or query.additional or query.had_tsig:
            self.error(query, address, transport, dns.rcode.FORMERR)
            return
        task = asyncio.create_task(self.forward(query, address, transport))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    @staticmethod
    def error(query, address, transport, rcode):
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.flags &= ~dns.flags.AD
        response.set_rcode(rcode)
        transport.sendto(response.to_wire(max_size=512, prefer_truncation=True), address)

    async def forward(self, query, address, transport):
        try:
            upstream_query = copy.copy(query)
            upstream_query.id = secrets.randbits(16)
            limit = max(512, min(query.payload, 1232)) if query.edns >= 0 else 512
            if upstream_query.edns >= 0:
                upstream_query.use_edns(edns=query.edns, ednsflags=query.ednsflags,
                                        payload=limit, options=query.options)
            response = await exchange_udp(upstream_query, self.config)
            changed = strip_hints(response)
            response.id = query.id
            wire = response.to_wire(max_size=limit, prefer_truncation=True)
            transport.sendto(wire, address)
            LOG.debug("reply to %s: hints_removed=%s", address[0], changed)
        except (dns.exception.DNSException, OSError, ValueError, asyncio.TimeoutError):
            LOG.debug("upstream request failed", exc_info=True)
            self.error(query, address, transport, dns.rcode.SERVFAIL)
        except Exception:
            LOG.exception("unexpected forwarding error")
            self.error(query, address, transport, dns.rcode.SERVFAIL)

    async def close(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Listener(asyncio.DatagramProtocol):
    def __init__(self, forwarder):
        self.forwarder = forwarder

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.forwarder.receive(data, address, self.transport)

    def error_received(self, error):
        LOG.debug("UDP socket error: %s", error)


async def serve(config):
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    forwarder = Forwarder(config)
    transports = []
    try:
        for address in config.listen:
            family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            try:
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.setblocking(False)
                sock.bind((address, config.port))
                transport, _ = await loop.create_datagram_endpoint(lambda: Listener(forwarder), sock=sock)
            except BaseException:
                sock.close()
                raise
            transports.append(transport)
            LOG.info("UDP %s:%s -> %s:%s", address, config.port, config.upstream, config.upstream_port)
        await stop.wait()
    finally:
        for transport in transports:
            transport.close()
        await forwarder.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="JSON configuration file")
    parser.add_argument("--check-config", action="store_true", help="validate configuration and exit")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")
    try:
        config = Config.load(args.config)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    if args.check_config:
        print("Configuration OK")
        return
    try:
        asyncio.run(serve(config))
    except OSError as exc:
        parser.exit(1, f"Cannot start DNS forwarder: {exc}\n")


if __name__ == "__main__":
    main()
