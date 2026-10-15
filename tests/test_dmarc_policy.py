"""Tests for parsedmarc.dmarc_policy (RFC 9989 DMARC policy discovery).

DNS is faked at the dnspython boundary (``dns.resolver.Resolver.resolve``,
see ``tests/dnsfake.py``), so ``parsedmarc.utils.query_dns`` and the TXT
rendering it does run for real. Section numbers refer to RFC 9989.
"""

from __future__ import annotations

import unittest

import dns.resolver

from parsedmarc.dmarc_policy import (
    discover_dmarc_policy,
    parse_dmarc_record,
    to_a_label,
)
from tests.dnsfake import FakeDNS


class TestParseDmarcRecord(unittest.TestCase):
    """parse_dmarc_record follows the §4.7 tag definitions and the §4.8
    ABNF."""

    def test_full_record(self):
        record = parse_dmarc_record(
            "v=DMARC1; p=reject; sp=quarantine; np=none; adkim=s; aspf=s; "
            "rua=mailto:agg@example.com; ruf=mailto:fail@example.com; "
            "fo=1:d; psd=n; t=y"
        )
        assert record is not None
        self.assertEqual(record["p"], "reject")
        self.assertEqual(record["sp"], "quarantine")
        self.assertEqual(record["np"], "none")
        self.assertEqual(record["adkim"], "s")
        self.assertEqual(record["aspf"], "s")
        self.assertEqual(record["rua"], ["mailto:agg@example.com"])
        self.assertEqual(record["ruf"], ["mailto:fail@example.com"])
        self.assertEqual(record["fo"], "1:d")
        self.assertEqual(record["psd"], "n")
        self.assertEqual(record["t"], "y")
        self.assertTrue(record["raw"].startswith("v=DMARC1; p=reject"))

    def test_defaults_for_absent_tags(self):
        """§4.7: an absent "p" is treated as p=none; adkim/aspf default to
        "r", fo to "0", psd to "u", t to "n". sp and np stay None because
        their fallbacks depend on where the record is applied."""
        record = parse_dmarc_record("v=DMARC1")
        self.assertEqual(
            record,
            {
                "raw": "v=DMARC1",
                "p": "none",
                "sp": None,
                "np": None,
                "adkim": "r",
                "aspf": "r",
                "fo": "0",
                "psd": "u",
                "t": "n",
                "rua": [],
                "ruf": [],
            },
        )

    def test_version_must_be_first_and_exact(self):
        """§4.7: "v" MUST be the first tag and its value "DMARC1" is case
        sensitive (§4.8 %s"DMARC1"); otherwise the record is ignored."""
        self.assertIsNone(parse_dmarc_record("p=reject; v=DMARC1"))
        self.assertIsNone(parse_dmarc_record("v=DMARC2; p=reject"))
        self.assertIsNone(parse_dmarc_record("v=dmarc1; p=reject"))
        self.assertIsNone(parse_dmarc_record("v=DMARC10; p=reject"))
        self.assertIsNone(parse_dmarc_record("v=spf1 -all"))
        self.assertIsNone(parse_dmarc_record(""))

    def test_whitespace_around_separators(self):
        """§4.8: dmarc-sep = *WSP ";" *WSP and equals = *WSP "=" *WSP; a
        trailing separator is allowed."""
        record = parse_dmarc_record(" v = DMARC1 ;\tp = quarantine ; ")
        assert record is not None
        self.assertEqual(record["p"], "quarantine")

    def test_unknown_tags_are_ignored(self):
        """§4.7: "unknown tags MUST be ignored" — the record stays valid.
        Tag names are case-sensitive (RFC 6376 §3.2, whose tag-value syntax
        §4.7 adopts), so "P" is an unknown tag, not "p"."""
        record = parse_dmarc_record("v=DMARC1; foo=bar; P=reject; p=quarantine")
        assert record is not None
        self.assertEqual(record["p"], "quarantine")
        record = parse_dmarc_record("v=DMARC1; P=reject")
        assert record is not None
        self.assertEqual(record["p"], "none")

    def test_historic_tags_are_not_parsed(self):
        """pct, rf, and ri are "historic" in the §9 DMARC Tags registry:
        they are neither parsed nor defaulted, and an out-of-range pct does
        not invalidate the record."""
        record = parse_dmarc_record("v=DMARC1; p=reject; pct=101; ri=x; rf=afrf")
        assert record is not None
        self.assertEqual(record["p"], "reject")
        for tag in ("pct", "rf", "ri"):
            self.assertNotIn(tag, record)

    def test_policy_values_are_case_insensitive(self):
        """The §4.8 dmarc-request values are ABNF quoted strings, which are
        case-insensitive (RFC 5234 §2.3)."""
        record = parse_dmarc_record("v=DMARC1; p=Reject; sp=NONE; adkim=S")
        assert record is not None
        self.assertEqual(record["p"], "reject")
        self.assertEqual(record["sp"], "none")
        self.assertEqual(record["adkim"], "s")

    def test_invalid_p_with_valid_rua_acts_as_p_none(self):
        """§4.10.1: a record without a valid "p" tag, or with an invalid
        "sp" or "np" tag, acts as "p=none" when "rua" holds at least one
        syntactically valid URI."""
        for text in (
            "v=DMARC1; p=bogus; sp=reject; np=reject; rua=mailto:a@example.com",
            "v=DMARC1; p=reject; sp=bogus; rua=mailto:a@example.com",
            "v=DMARC1; p=reject; np=bogus; rua=mailto:a@example.com",
        ):
            with self.subTest(record=text):
                record = parse_dmarc_record(text)
                assert record is not None
                self.assertEqual(record["p"], "none")
                self.assertIsNone(record["sp"])
                self.assertIsNone(record["np"])
                self.assertEqual(record["rua"], ["mailto:a@example.com"])

    def test_invalid_policy_without_valid_rua_is_unusable(self):
        """§4.10.1: without a valid rua URI, "the Mail Receiver applies no
        DMARC processing", so there is no usable record."""
        for text in (
            "v=DMARC1; p=bogus",
            "v=DMARC1; p=reject; sp=bogus",
            "v=DMARC1; p=reject; np=bogus",
            "v=DMARC1; p=bogus; rua=not a uri",
        ):
            with self.subTest(record=text):
                self.assertIsNone(parse_dmarc_record(text))

    def test_one_valid_rua_uri_is_enough(self):
        """§4.10.1 asks for "at least one syntactically valid reporting
        URI"; a malformed entry beside it is dropped, not fatal."""
        record = parse_dmarc_record(
            "v=DMARC1; p=bogus; rua=mailto:a@example.com,b@example.com"
        )
        assert record is not None
        self.assertEqual(record["p"], "none")
        self.assertEqual(record["rua"], ["mailto:a@example.com"])

    def test_uri_list_drops_obsolete_size_suffix(self):
        """§4.8: obs-dmarc-uri = dmarc-uri "!" 1*DIGIT [k/m/g/t]; the size
        suffix is obsolete. URIs are separated by *WSP "," *WSP."""
        record = parse_dmarc_record(
            "v=DMARC1; p=none; rua=mailto:a@example.com!10m , "
            "https://reports.example.com/r!5"
        )
        assert record is not None
        self.assertEqual(
            record["rua"],
            ["mailto:a@example.com", "https://reports.example.com/r"],
        )

    def test_malformed_optional_values_fall_back_to_defaults(self):
        """§4.8: syntax errors are "discarded in favor of default values (if
        any)"."""
        record = parse_dmarc_record(
            "v=DMARC1; p=reject; adkim=x; aspf=relaxed; fo=2; psd=maybe; t=yes"
        )
        assert record is not None
        self.assertEqual(record["p"], "reject")
        self.assertEqual(record["adkim"], "r")
        self.assertEqual(record["aspf"], "r")
        self.assertEqual(record["fo"], "0")
        self.assertEqual(record["psd"], "u")
        self.assertEqual(record["t"], "n")

    def test_fo_options_at_most_once(self):
        """§4.8 dmarc-afrf: "each may appear at most once in dmarc-fo"."""
        valid = parse_dmarc_record("v=DMARC1; fo=0:S")
        repeated = parse_dmarc_record("v=DMARC1; fo=1:1")
        assert valid is not None and repeated is not None
        self.assertEqual(valid["fo"], "0:s")
        self.assertEqual(repeated["fo"], "0")

    def test_malformed_segments_are_skipped(self):
        """A segment that is not name=value with a 1*ALPHA name and a
        non-empty value (§4.8 dmarc-tag) is a syntax error and ignored."""
        record = parse_dmarc_record("v=DMARC1; junk; p=; x-y=1; p=reject")
        assert record is not None
        self.assertEqual(record["p"], "reject")

    def test_duplicate_tag_invalidates_record(self):
        """RFC 6376 §3.2 (the tag-value syntax §4.7 adopts): "if a tag name
        does occur more than once, the entire tag-list is invalid"."""
        self.assertIsNone(parse_dmarc_record("v=DMARC1; p=none; p=reject"))


class TestToALabel(unittest.TestCase):
    def test_normalizes_case_trailing_dot_and_idn(self):
        self.assertEqual(to_a_label(" Example.COM. "), "example.com")
        self.assertEqual(to_a_label("bücher.example"), "xn--bcher-kva.example")

    def test_rejects_invalid_names(self):
        for name in ("", ".", "a..b", "a" * 64 + ".example"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    to_a_label(name)


class TestDiscoverDmarcPolicy(unittest.TestCase):
    """discover_dmarc_policy implements the §4.10 DNS Tree Walk, the
    §4.10.2 Organizational Domain selection, and §4.10.1 policy
    discovery."""

    def _discover(self, zone: FakeDNS, domain: str):
        with zone.patch():
            return discover_dmarc_policy(domain, nameservers=["192.0.2.53"])

    def test_record_at_author_domain_applies_p(self):
        """§4.10.1: a valid record at the Author Domain "is the DMARC Policy
        Record to be applied", and its "p" tag is the policy. The walk still
        continues up, for the Organizational Domain (§4.10.2)."""
        zone = FakeDNS(txt={"_dmarc.example.com": ["v=DMARC1; p=reject; sp=none"]})
        result = self._discover(zone, "Example.COM.")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["record_domain"], "example.com")
        self.assertEqual(result["organizational_domain"], "example.com")
        self.assertEqual(result["effective_policy"], "reject")
        self.assertIsNone(result["domain_exists"])
        assert result["record"] is not None
        self.assertEqual(result["record"]["sp"], "none")
        self.assertEqual(zone.names(), ["_dmarc.example.com", "_dmarc.com"])

    def test_subdomain_uses_org_domain_sp(self):
        """§4.10.1: for a subdomain of the Organizational Domain, "sp"
        applies when the subdomain exists. With no "np", "np" falls back to
        "sp" (§4.7), so existence does not matter and is not queried."""
        zone = FakeDNS(
            txt={"_dmarc.example.com": ["v=DMARC1; p=reject; sp=quarantine"]}
        )
        result = self._discover(zone, "mail.example.com")
        self.assertEqual(result["record_domain"], "example.com")
        self.assertEqual(result["organizational_domain"], "example.com")
        self.assertEqual(result["effective_policy"], "quarantine")
        self.assertIsNone(result["domain_exists"])
        self.assertEqual(zone.names("A"), [])
        self.assertEqual(
            zone.names(),
            ["_dmarc.mail.example.com", "_dmarc.example.com", "_dmarc.com"],
        )

    def test_subdomain_without_sp_uses_p(self):
        """§4.10.1: "In the absence of applicable "sp" or "np" tags, the "p"
        tag policy is used for subdomains"."""
        zone = FakeDNS(txt={"_dmarc.example.com": ["v=DMARC1; p=reject"]})
        result = self._discover(zone, "mail.example.com")
        self.assertEqual(result["effective_policy"], "reject")

    def test_np_applies_only_to_nonexistent_subdomain(self):
        """§4.7/§4.10.1: "np" applies when the subdomain does not exist —
        an NXDOMAIN response (§3.2.13) — and "sp" when it does, whether the
        name has A records or none (NODATA)."""
        record = "v=DMARC1; p=reject; sp=quarantine; np=none"
        cases = (
            (FakeDNS(txt={"_dmarc.example.com": [record]}), False, "none"),
            (
                FakeDNS(
                    txt={"_dmarc.example.com": [record]},
                    existing={"gone.example.com"},
                ),
                True,
                "quarantine",
            ),
            (
                FakeDNS(
                    txt={"_dmarc.example.com": [record]},
                    a={"gone.example.com": ["192.0.2.1"]},
                ),
                True,
                "quarantine",
            ),
        )
        for zone, exists, policy in cases:
            with self.subTest(exists=exists, policy=policy):
                result = self._discover(zone, "gone.example.com")
                self.assertIs(result["domain_exists"], exists)
                self.assertEqual(result["effective_policy"], policy)
                self.assertEqual(zone.names("A"), ["gone.example.com"])

    def test_np_falls_back_to_p_when_sp_absent(self):
        """§4.7: without "np", the "sp" policy applies to non-existent
        subdomains, or "p" if "sp" is absent too; an explicit np differing
        from p is what triggers the existence test."""
        zone = FakeDNS(
            txt={"_dmarc.example.com": ["v=DMARC1; p=quarantine; np=reject"]}
        )
        result = self._discover(zone, "gone.example.com")
        self.assertIs(result["domain_exists"], False)
        self.assertEqual(result["effective_policy"], "reject")

    def test_org_domain_is_fewest_labels_not_nearest_record(self):
        """§4.10.2: without psd tags, "select the DMARC Policy Record found
        at the name with the fewest number of labels", and §4.10.1 applies
        that Organizational Domain's record, not the nearest one."""
        zone = FakeDNS(
            txt={
                "_dmarc.mail.example.com": ["v=DMARC1; p=none"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        )
        result = self._discover(zone, "a.mail.example.com")
        self.assertEqual(result["organizational_domain"], "example.com")
        self.assertEqual(result["record_domain"], "example.com")
        self.assertEqual(result["effective_policy"], "reject")

    def test_psd_n_stops_walk_and_is_org_domain(self):
        """§4.10 step 6 stops the walk at a record with psd=n, and §4.10.2
        makes that record's domain the Organizational Domain."""
        zone = FakeDNS(
            txt={
                "_dmarc.mail.example.com": ["v=DMARC1; p=quarantine; psd=n"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        )
        result = self._discover(zone, "a.mail.example.com")
        self.assertEqual(result["organizational_domain"], "mail.example.com")
        self.assertEqual(result["record_domain"], "mail.example.com")
        self.assertEqual(result["effective_policy"], "quarantine")
        self.assertEqual(
            zone.names(), ["_dmarc.a.mail.example.com", "_dmarc.mail.example.com"]
        )

    def test_psd_y_makes_the_domain_below_it_the_org_domain(self):
        """§4.10.2: a psd=y record (not at the walk's start) makes "the
        domain one label below this one" the Organizational Domain. With no
        record there, §4.10.1 falls back to the PSD's record, whose sp or np
        applies to the subdomain."""
        zone = FakeDNS(
            txt={"_dmarc.example": ["v=DMARC1; p=reject; sp=quarantine; psd=y"]}
        )
        result = self._discover(zone, "a.mail.corp.example")
        self.assertEqual(result["organizational_domain"], "corp.example")
        self.assertEqual(result["record_domain"], "example")
        self.assertEqual(result["effective_policy"], "quarantine")
        self.assertEqual(
            zone.names(),
            [
                "_dmarc.a.mail.corp.example",
                "_dmarc.mail.corp.example",
                "_dmarc.corp.example",
                "_dmarc.example",
            ],
        )

    def test_psd_policy_not_used_when_org_domain_has_record(self):
        """§4.10.1: "PSD policy is not used for Organizational Domains that
        have published a DMARC Policy Record"."""
        zone = FakeDNS(
            txt={
                "_dmarc.example.com": ["v=DMARC1; p=none"],
                "_dmarc.com": ["v=DMARC1; p=reject; psd=y"],
            }
        )
        result = self._discover(zone, "a.example.com")
        self.assertEqual(result["organizational_domain"], "example.com")
        self.assertEqual(result["record_domain"], "example.com")
        self.assertEqual(result["effective_policy"], "none")

    def test_psd_y_at_start_of_walk(self):
        """§4.10 step 2 stops at the starting domain's psd=y record, and
        §4.10.2 excludes it from the psd=y rule, so the fewest-labels rule
        makes the starting domain the Organizational Domain."""
        zone = FakeDNS(txt={"_dmarc.example": ["v=DMARC1; p=reject; psd=y"]})
        result = self._discover(zone, "example")
        self.assertEqual(result["organizational_domain"], "example")
        self.assertEqual(result["record_domain"], "example")
        self.assertEqual(result["effective_policy"], "reject")
        self.assertEqual(zone.names(), ["_dmarc.example"])

    def test_walk_makes_at_most_eight_queries(self):
        """§4.10 steps 3-4: after the first query, a name with eight or more
        labels is shortened to seven, so "Author Domains with more than
        eight labels do not result in more than eight DNS queries"."""
        long_name = "a.b.c.d.e.f.g.h.i.j.mail.example.com"
        zone = FakeDNS()
        result = self._discover(zone, long_name)
        self.assertIsNone(result["record"])
        self.assertEqual(
            zone.names(),
            [
                f"_dmarc.{long_name}",
                "_dmarc.g.h.i.j.mail.example.com",
                "_dmarc.h.i.j.mail.example.com",
                "_dmarc.i.j.mail.example.com",
                "_dmarc.j.mail.example.com",
                "_dmarc.mail.example.com",
                "_dmarc.example.com",
                "_dmarc.com",
            ],
        )

    def test_walk_query_count_for_short_and_eight_label_names(self):
        """A name with fewer than eight labels loses one label per query; a
        name with exactly eight also makes eight queries."""
        for labels in (1, 2, 7, 8):
            with self.subTest(labels=labels):
                zone = FakeDNS()
                name = ".".join(f"l{i}" for i in range(labels))
                self._discover(zone, name)
                self.assertEqual(len(zone.names()), labels)

    def test_no_record_means_dmarc_does_not_apply(self):
        """§4.10.1: with no record, "Mail Receivers MUST NOT apply the DMARC
        mechanism"; §4.10.2: the initial target is the Organizational
        Domain."""
        zone = FakeDNS(existing={"_dmarc.example.com"})
        result = self._discover(zone, "example.com")
        self.assertEqual(
            result,
            {
                "domain": "example.com",
                "record": None,
                "record_domain": None,
                "organizational_domain": "example.com",
                "effective_policy": None,
                "domain_exists": None,
            },
        )

    def test_multiple_dmarc_records_are_all_discarded(self):
        """§4.10 step 2: "If multiple DMARC Policy Records are returned for a
        single target, they are all discarded" and the walk continues; TXT
        records that do not start with v=DMARC1 are discarded first."""
        zone = FakeDNS(
            txt={
                "_dmarc.mail.example.com": [
                    "v=DMARC1; p=none",
                    "v=DMARC1; p=reject",
                ],
                "_dmarc.example.com": [
                    "site-verification=abc123",
                    "v=DMARC1; p=quarantine",
                ],
            }
        )
        result = self._discover(zone, "mail.example.com")
        self.assertEqual(result["record_domain"], "example.com")
        self.assertEqual(result["effective_policy"], "quarantine")

    def test_duplicate_tag_record_is_not_a_record(self):
        """A record repeating a tag is an invalid tag-list (RFC 6376 §3.2),
        so the walk treats the name as having no record."""
        zone = FakeDNS(
            txt={
                "_dmarc.mail.example.com": ["v=DMARC1; p=none; p=none"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        )
        result = self._discover(zone, "mail.example.com")
        self.assertEqual(result["record_domain"], "example.com")

    def test_multi_string_txt_record_is_concatenated(self):
        """A record longer than one 255-byte character-string is split into
        several; they are concatenated with no separator (RFC 6376
        §3.6.2.2, whose tag-value syntax RFC 9989 §4.7 adopts). Splitting
        inside "reject" would otherwise yield an invalid p."""
        zone = FakeDNS(
            txt={
                "_dmarc.example.com": [
                    '"v=DMARC1; p=rej" "ect; rua=mailto:a@ex" "ample.com"'
                ]
            }
        )
        result = self._discover(zone, "example.com")
        assert result["record"] is not None
        self.assertEqual(result["record"]["p"], "reject")
        self.assertEqual(result["record"]["rua"], ["mailto:a@example.com"])

    def test_unusable_author_record_falls_back_to_org_domain(self):
        """§4.10.1 applies the Author Domain's record only "If a valid DMARC
        Policy Record is found there"; an unusable one (invalid p, no rua)
        is passed over for the Organizational Domain's."""
        zone = FakeDNS(
            txt={
                "_dmarc.mail.example.com": ["v=DMARC1; p=bogus"],
                "_dmarc.example.com": ["v=DMARC1; p=reject"],
            }
        )
        result = self._discover(zone, "mail.example.com")
        self.assertEqual(result["record_domain"], "example.com")
        self.assertEqual(result["effective_policy"], "reject")

    def test_unusable_record_at_org_domain_means_no_dmarc(self):
        """§4.10.1: a selected record without a valid p and without a valid
        rua means "no DMARC processing"; a nearer record is not used
        instead."""
        zone = FakeDNS(
            txt={
                "_dmarc.mail.example.com": ["v=DMARC1; p=none"],
                "_dmarc.example.com": ["v=DMARC1; p=bogus"],
            }
        )
        result = self._discover(zone, "a.mail.example.com")
        self.assertEqual(result["organizational_domain"], "example.com")
        self.assertIsNone(result["record"])
        self.assertIsNone(result["record_domain"])
        self.assertIsNone(result["effective_policy"])

    def test_unusable_record_at_author_domain_that_is_org_domain(self):
        """When the only record is the Author Domain's own and it is
        unusable, there is no other record to fall back to."""
        zone = FakeDNS(txt={"_dmarc.example.com": ["v=DMARC1; p=bogus"]})
        result = self._discover(zone, "example.com")
        self.assertEqual(result["organizational_domain"], "example.com")
        self.assertIsNone(result["record"])

    def test_idn_is_queried_in_a_label_form(self):
        zone = FakeDNS(txt={"_dmarc.xn--bcher-kva.example": ["v=DMARC1; p=reject"]})
        result = self._discover(zone, "Bücher.example")
        self.assertEqual(result["domain"], "xn--bcher-kva.example")
        self.assertEqual(result["effective_policy"], "reject")
        self.assertEqual(zone.names()[0], "_dmarc.xn--bcher-kva.example")

    def test_dns_error_in_walk_propagates(self):
        """§4.10.1 leaves DNS errors to the receiver. A failed query is not
        treated as "no record" (that could pick the wrong Organizational
        Domain); the error propagates."""
        zone = FakeDNS(
            txt={"_dmarc.example.com": ["v=DMARC1; p=reject"]},
            errors={"_dmarc.mail.example.com": dns.resolver.NoNameservers()},
        )
        with self.assertRaises(dns.resolver.NoNameservers):
            self._discover(zone, "mail.example.com")

    def test_dns_error_in_existence_test_propagates(self):
        zone = FakeDNS(
            txt={"_dmarc.example.com": ["v=DMARC1; p=reject; np=none"]},
            errors={"mail.example.com": dns.resolver.NoNameservers()},
        )
        with self.assertRaises(dns.resolver.NoNameservers):
            self._discover(zone, "mail.example.com")

    def test_invalid_domain_raises_value_error(self):
        zone = FakeDNS()
        with self.assertRaises(ValueError):
            self._discover(zone, "a..example.com")
        self.assertEqual(zone.queries, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
