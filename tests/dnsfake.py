"""A fake DNS zone served at the dnspython SDK boundary.

``FakeDNS.patch()`` replaces ``dns.resolver.Resolver.resolve``, the call
``parsedmarc.utils.query_dns`` makes for every lookup, so the code under
test runs unchanged down to the resolver and only the network is faked.
Answers are real dnspython rdata objects, so TXT records go through the
same rendering as a live answer.
"""

from __future__ import annotations

from unittest.mock import patch

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver


class FakeDNS:
    """A tiny zone: TXT records, names that exist with no data of the
    queried type, and names that fail with a given exception.

    Any other name is NXDOMAIN. ``queries`` records every ``(name, type)``
    pair asked of the resolver, in order.
    """

    def __init__(
        self,
        txt: dict[str, list[str]] | None = None,
        existing: set[str] | None = None,
        a: dict[str, list[str]] | None = None,
        errors: dict[str, Exception] | None = None,
    ):
        # Each TXT value is the record in zone-file presentation form, so a
        # multi-string record is written '"first chunk" "second chunk"'; a
        # value without a quote is wrapped as a single string.
        self.txt = txt or {}
        self.existing = existing or set()
        self.a = a or {}
        self.errors = errors or {}
        self.queries: list[tuple[str, str]] = []

    def resolve(self, name, rdtype, *args, **kwargs):
        name = str(name).rstrip(".").lower()
        rdtype = str(rdtype).upper()
        self.queries.append((name, rdtype))
        if name in self.errors:
            raise self.errors[name]
        if rdtype == "TXT" and name in self.txt:
            return [
                dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.TXT,
                    value if '"' in value else f'"{value}"',
                )
                for value in self.txt[name]
            ]
        if rdtype == "A" and name in self.a:
            return [
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, address)
                for address in self.a[name]
            ]
        if name in self.existing or name in self.txt or name in self.a:
            raise dns.resolver.NoAnswer()
        raise dns.resolver.NXDOMAIN()

    def patch(self):
        """Return a context manager that serves this zone to every query."""
        return patch.object(dns.resolver.Resolver, "resolve", side_effect=self.resolve)

    def names(self, rdtype: str = "TXT") -> list[str]:
        """The names queried for *rdtype*, in order."""
        return [name for name, kind in self.queries if kind == rdtype]
