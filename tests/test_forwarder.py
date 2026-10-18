import asyncio
import dataclasses
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path

import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
from dns.rdtypes.svcbbase import ParamKey

from dns_hint_filter import Config, Forwarder, Listener, strip_hints


def rr(kind, *records, name="example.test."):
    return dns.rrset.from_text(name, 120, "IN", kind, *records)


def response():
    return dns.message.make_response(dns.message.make_query("example.test", "HTTPS"))


class RewriteTests(unittest.TestCase):
    def test_all_sections_and_multiple_records_preserve_other_fields(self):
        message = response()
        # A length-prefixed ECHConfigList with one unknown-version entry.
        # Keep it structurally valid even when dnspython validates ECH framing.
        text = '1 . mandatory=alpn,ipv4hint,ipv6hint alpn=h2,h3 port=8443 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1 ech=AAT//wAA key65400="opaque"'
        original = rr("HTTPS", text, '2 target.test. ipv4hint=192.0.2.2')[0]
        for section in (message.answer, message.authority, message.additional):
            section.append(rr("HTTPS", text, '2 target.test. ipv4hint=192.0.2.2'))
        self.assertTrue(strip_hints(message))
        parsed = dns.message.from_wire(message.to_wire())
        for section in (parsed.answer, parsed.authority, parsed.additional):
            self.assertEqual(section[0].ttl, 120)
            self.assertEqual(len(section[0]), 2)
            record = next(r for r in section[0] if r.priority == 1)
            self.assertEqual(record.target, original.target)
            self.assertEqual(record.params[ParamKey.MANDATORY].keys, (ParamKey.ALPN,))
            for key in (ParamKey.ALPN, ParamKey.PORT, ParamKey.ECH, 65400):
                self.assertEqual(record.params[key].to_text(), original.params[key].to_text())
            for record in section[0]:
                self.assertNotIn(ParamKey.IPV4HINT, record.params)
                self.assertNotIn(ParamKey.IPV6HINT, record.params)
        self.assertFalse(strip_hints(parsed))

    def test_empty_mandatory_removed(self):
        message = response()
        message.answer.append(rr("HTTPS", '1 . mandatory=ipv4hint ipv4hint=192.0.2.1'))
        strip_hints(message)
        self.assertEqual(dict(message.answer[0][0].params), {})
        dns.message.from_wire(message.to_wire())

    def test_alias_cname_address_svcb_and_no_hints_unchanged(self):
        message = response()
        message.flags |= dns.flags.AD
        message.answer.extend([rr("HTTPS", "0 target.test."), rr("CNAME", "target.test.")])
        message.additional.extend([rr("A", "192.0.2.1"), rr("AAAA", "2001:db8::1"),
                                   rr("SVCB", "1 . ipv4hint=192.0.2.1"),
                                   rr("HTTPS", "1 . alpn=h2", name="target.test.")])
        before = message.to_text()
        self.assertFalse(strip_hints(message))
        self.assertEqual(message.to_text(), before)

    def test_dnssec_removes_only_signature_for_changed_rrset(self):
        message = response()
        message.flags |= dns.flags.AD
        message.answer.extend([
            rr("HTTPS", "1 . ipv6hint=2001:db8::1"),
            rr("RRSIG", "HTTPS 13 2 120 20300101000000 20200101000000 1 test. AA=="),
            rr("RRSIG", "A 13 2 120 20300101000000 20200101000000 1 test. AA=="),
            rr("RRSIG", "HTTPS 13 2 120 20300101000000 20200101000000 1 test. AA==", name="other.test.")])
        strip_hints(message)
        self.assertFalse(message.flags & dns.flags.AD)
        self.assertEqual(len(message.answer), 3)
        self.assertEqual(message.answer[1].covers, dns.rdatatype.A)
        self.assertEqual(str(message.answer[2].name), "other.test.")


class ConfigTests(unittest.TestCase):
    def load(self, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(dict(upstream="192.0.2.53", **kwargs)))
            return Config.load(path)

    def test_acl_ipv4_ipv6_and_mapped(self):
        config = self.load(allow=["192.0.2.0/24", "2001:db8::/32"])
        for address in ("192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"):
            self.assertTrue(config.allows(address))
        for address in ("198.51.100.1", "2001:db9::1", "127.0.0.1"):
            self.assertFalse(config.allows(address))

    def test_reject_invalid_settings(self):
        for kwargs in ({"port": 0}, {"port": True}, {"timeout": -1},
                       {"timeout": float("nan")}, {"allow": []}, {"allow": ["192.0.2.1/24"]},
                       {"listen": ["hostname"]}, {"typo": 1}, {"max_inflight": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.load(**kwargs)

    def test_wildcard_listening(self):
        self.assertEqual(self.load(listen=["0.0.0.0"]).listen, ("0.0.0.0",))


class FakeUpstream(asyncio.DatagramProtocol):
    def __init__(self):
        self.count = 0
        self.mode = "normal"

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, wire, address):
        self.count += 1
        query = dns.message.from_wire(wire)
        if self.mode == "timeout":
            return
        reply = dns.message.make_response(query)
        reply.flags |= dns.flags.RA | dns.flags.AD
        if self.mode == "nxdomain":
            reply.set_rcode(dns.rcode.NXDOMAIN)
        elif self.mode == "truncated":
            reply.flags |= dns.flags.TC
        elif self.mode == "large":
            reply.answer.append(rr("TXT", *['"' + str(i) + 'x' * 200 + '"' for i in range(10)]))
        elif query.question[0].rdtype == dns.rdatatype.HTTPS:
            reply.answer.append(rr("HTTPS", "1 . alpn=h2 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1",
                                   name=str(query.question[0].name)))
        else:
            reply.answer.append(rr("A", "192.0.2.1", name=str(query.question[0].name)))
        if self.mode == "bad_then_good":
            reply.id ^= 1
            self.transport.sendto(reply.to_wire(), address)
            reply.id ^= 1
            saved = reply.question
            reply.question = dns.message.make_query("wrong.test", "HTTPS").question
            self.transport.sendto(reply.to_wire(), address)
            reply.question = saved
            self.transport.sendto(b"invalid", address)
        self.transport.sendto(reply.to_wire(max_size=65535), address)


class UDPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loop = asyncio.get_running_loop()
        self.upstream_transport, self.upstream = await loop.create_datagram_endpoint(
            FakeUpstream, local_addr=("127.0.0.1", 0))
        config = Config(("127.0.0.1",), 5353, (ipaddress.ip_network("127.0.0.0/8"),),
                        "127.0.0.1", self.upstream_transport.get_extra_info("sockname")[1], 0.08, 256)
        self.forwarder = Forwarder(config)
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: Listener(self.forwarder), local_addr=("127.0.0.1", 0))
        self.port = self.transport.get_extra_info("sockname")[1]

    async def asyncTearDown(self):
        self.transport.close()
        self.upstream_transport.close()
        await self.forwarder.close()

    async def query(self, kind="HTTPS", name="example.test", **kwargs):
        query = dns.message.make_query(name, kind, **kwargs)
        reply = await dns.asyncquery.udp(query, "127.0.0.1", port=self.port, timeout=1)
        self.assertEqual(reply.id, query.id)
        return reply

    async def test_rewrite_over_udp(self):
        reply = await self.query(use_edns=True, want_dnssec=True)
        self.assertEqual(str(reply.answer[0][0]), '1 . alpn="h2"')
        self.assertFalse(reply.flags & dns.flags.AD)

    async def test_a_passthrough(self):
        reply = await self.query("A")
        self.assertEqual(str(reply.answer[0][0]), "192.0.2.1")
        self.assertTrue(reply.flags & dns.flags.AD)

    async def test_mismatched_and_malformed_packets_ignored(self):
        self.upstream.mode = "bad_then_good"
        self.assertEqual((await self.query()).rcode(), dns.rcode.NOERROR)

    async def test_timeout_servfail(self):
        self.upstream.mode = "timeout"
        self.assertEqual((await self.query()).rcode(), dns.rcode.SERVFAIL)

    async def test_nxdomain_and_tc_preserved(self):
        self.upstream.mode = "nxdomain"
        self.assertEqual((await self.query()).rcode(), dns.rcode.NXDOMAIN)
        self.upstream.mode = "truncated"
        self.assertTrue((await self.query()).flags & dns.flags.TC)

    async def test_oversized_response_is_truncated(self):
        self.upstream.mode = "large"
        for options, limit in (({}, 512), ({"use_edns": True, "payload": 800}, 800)):
            reply = await self.query("TXT", **options)
            self.assertLessEqual(len(reply.wire), limit)
            self.assertTrue(reply.flags & dns.flags.TC)

    async def test_parallel_clients_same_id(self):
        async def one(index):
            query = dns.message.make_query(f"host{index}.test", "HTTPS")
            query.id = 42
            reply = await dns.asyncquery.udp(query, "127.0.0.1", port=self.port, timeout=1)
            self.assertEqual(reply.id, 42)
            self.assertEqual(reply.answer[0].name, query.question[0].name)
        await asyncio.gather(*(one(index) for index in range(25)))

    async def test_denied_source_and_overload_never_reach_upstream(self):
        self.forwarder.config = dataclasses.replace(self.forwarder.config,
            allowed_networks=(ipaddress.ip_network("192.0.2.0/24"),))
        query = dns.message.make_query("example.test", "HTTPS")
        with self.assertRaises(dns.exception.Timeout):
            await dns.asyncquery.udp(query, "127.0.0.1", port=self.port, timeout=0.05)
        self.assertEqual(self.upstream.count, 0)
        self.forwarder.config = dataclasses.replace(self.forwarder.config,
            allowed_networks=(ipaddress.ip_network("127.0.0.0/8"),), max_inflight=1)
        pending = asyncio.create_task(asyncio.sleep(10))
        self.forwarder.tasks.add(pending)
        with self.assertRaises(dns.exception.Timeout):
            await dns.asyncquery.udp(query, "127.0.0.1", port=self.port, timeout=0.05)
        self.assertEqual(self.upstream.count, 0)


if __name__ == "__main__":
    unittest.main()
