"""Deadline-bound public-only transport with pinned DNS and no ambient proxies."""

import asyncio
import ipaddress
import socket
import ssl

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver
from aiohttp.abc import AbstractResolver

from .target import InvalidTarget, is_public


class PublicResolver(AbstractResolver):
    def __init__(self):
        self.records = {}
        self._locks = {}
        self.resolver = dns.asyncresolver.Resolver()

    async def addresses(self, host):
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with lock:
            return await self._addresses_once(host)

    async def _addresses_once(self, host):
        if host in self.records:
            return self.records[host]
        try:
            ipaddress.ip_address(host)
        except ValueError:

            async def query(kind):
                try:
                    answer = await self.resolver.resolve(host, kind, search=False, lifetime=2.5)
                    return [item.address for item in answer]
                except dns.resolver.NoAnswer:
                    return []

            try:
                async with asyncio.timeout(3):
                    answers = await asyncio.gather(query("A"), query("AAAA"))
                addresses = sorted(set(answers[0] + answers[1]))
            except (dns.exception.DNSException, TimeoutError):
                raise OSError("DNS resolution failed or timed out") from None
        else:
            addresses = [host]
        if not addresses or not all(is_public(address) for address in addresses):
            raise InvalidTarget(
                "DNS yanıtı özel/ayrılmış adres içeriyor; hedefe bağlantı engellendi."
            )
        self.records[host] = addresses
        return addresses

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        addresses = await self.addresses(host)
        return [
            dict(
                hostname=host,
                host=address,
                port=port,
                family=socket.AF_INET6 if ":" in address else socket.AF_INET,
                proto=0,
                flags=socket.AI_NUMERICHOST,
            )
            for address in addresses
        ]

    async def close(self):
        return None


def session_for(resolver):
    context = ssl.create_default_context()
    connector = aiohttp.TCPConnector(
        resolver=resolver, use_dns_cache=False, ssl=context, limit=3, force_close=True
    )
    return aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=5, connect=3, sock_read=2),
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=False,
        auto_decompress=False,
        max_line_size=8192,
        max_field_size=8192,
        max_headers=64,
        headers={"User-Agent": "T3-Inspector/0.1", "Accept-Encoding": "identity"},
    )


async def read_bounded(response, maximum):
    data = bytearray()
    async for chunk in response.content.iter_chunked(8192):
        remaining = maximum + 1 - len(data)
        data.extend(chunk[:remaining])
        if len(data) > maximum:
            return bytes(data[:maximum]), True
    return bytes(data), False
