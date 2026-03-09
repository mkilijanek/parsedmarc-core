#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import os
import unittest
from glob import glob

from lxml import etree

import parsedmarc
import parsedmarc.utils

# Detect if running in GitHub Actions to skip DNS lookups
OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"


def minify_xml(xml_string):
    parser = etree.XMLParser(remove_blank_text=True)
    tree = etree.fromstring(xml_string.encode("utf-8"), parser)
    return etree.tostring(tree, pretty_print=False).decode("utf-8")


def compare_xml(xml1, xml2):
    parser = etree.XMLParser(remove_blank_text=True)
    tree1 = etree.fromstring(xml1.encode("utf-8"), parser)
    tree2 = etree.fromstring(xml2.encode("utf-8"), parser)
    return etree.tostring(tree1) == etree.tostring(tree2)


class Test(unittest.TestCase):
    def testBase64Decoding(self):
        """Test base64 decoding"""
        # Example from Wikipedia Base64 article
        b64_str = "YW55IGNhcm5hbCBwbGVhcw"
        decoded_str = parsedmarc.utils.decode_base64(b64_str)
        assert decoded_str == b"any carnal pleas"

    def testPSLDownload(self):
        subdomain = "foo.example.com"
        result = parsedmarc.utils.get_base_domain(subdomain)
        assert result == "example.com"

        # Test newer PSL entries
        subdomain = "e3191.c.akamaiedge.net"
        result = parsedmarc.utils.get_base_domain(subdomain)
        assert result == "c.akamaiedge.net"

    def testExtractReportXMLComparator(self):
        """Test XML comparator function"""
        xmlnice_file = open("samples/extract_report/nice-input.xml")
        xmlnice = xmlnice_file.read()
        xmlnice_file.close()
        xmlchanged_file = open("samples/extract_report/changed-input.xml")
        xmlchanged = minify_xml(xmlchanged_file.read())
        xmlchanged_file.close()
        self.assertTrue(compare_xml(xmlnice, xmlnice))
        self.assertTrue(compare_xml(xmlchanged, xmlchanged))
        self.assertFalse(compare_xml(xmlnice, xmlchanged))
        self.assertFalse(compare_xml(xmlchanged, xmlnice))
        print("Passed!")

    def testExtractReportBytes(self):
        """Test extract report function for bytes string input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        with open(file, "rb") as f:
            data = f.read()
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report(data)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportXML(self):
        """Test extract report function for XML input"""
        print()
        file = "samples/extract_report/nice-input.xml"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportGZip(self):
        """Test extract report function for gzip input"""
        print()
        file = "samples/extract_report/nice-input.xml.gz"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testExtractReportZip(self):
        """Test extract report function for zip input"""
        print()
        file = "samples/extract_report/nice-input.xml.zip"
        print("Testing {0}: ".format(file), end="")
        xmlout = parsedmarc.extract_report_from_file_path(file)
        xmlin_file = open("samples/extract_report/nice-input.xml")
        xmlin = minify_xml(xmlin_file.read())
        xmlin_file.close()
        self.assertTrue(compare_xml(xmlout, xmlin))
        xmlin_file = open("samples/extract_report/changed-input.xml")
        xmlin = xmlin_file.read()
        xmlin_file.close()
        self.assertFalse(compare_xml(xmlout, xmlin))
        print("Passed!")

    def testAggregateSamples(self):
        """Test sample aggregate/rua DMARC reports"""
        print()
        sample_paths = glob("samples/aggregate/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            parsed_report = parsedmarc.parse_report_file(
                sample_path, always_use_local_files=True, offline=OFFLINE_MODE
            )["report"]
            parsedmarc.parsed_aggregate_reports_to_csv(parsed_report)
            print("Passed!")

    def testEmptySample(self):
        """Test empty/unparasable report"""
        with self.assertRaises(parsedmarc.ParserError):
            parsedmarc.parse_report_file("samples/empty.xml", offline=OFFLINE_MODE)

    def testForensicSamples(self):
        """Test sample forensic/ruf/failure DMARC reports"""
        print()
        sample_paths = glob("samples/forensic/*.eml")
        for sample_path in sample_paths:
            print("Testing {0}: ".format(sample_path), end="")
            with open(sample_path) as sample_file:
                sample_content = sample_file.read()
                parsed_report = parsedmarc.parse_report_email(
                    sample_content, offline=OFFLINE_MODE
                )["report"]
            parsed_report = parsedmarc.parse_report_file(
                sample_path, offline=OFFLINE_MODE
            )["report"]
            parsedmarc.parsed_forensic_reports_to_csv(parsed_report)
            print("Passed!")

    def testSmtpTlsSamples(self):
        """Test sample SMTP TLS reports"""
        print()
        sample_paths = glob("samples/smtp_tls/*")
        for sample_path in sample_paths:
            if os.path.isdir(sample_path):
                continue
            print("Testing {0}: ".format(sample_path), end="")
            parsed_report = parsedmarc.parse_report_file(
                sample_path, offline=OFFLINE_MODE
            )["report"]
            parsedmarc.parsed_smtp_tls_reports_to_csv(parsed_report)
            print("Passed!")


class _FakePSL:
    def privatesuffix(self, domain):
        domain = domain.lower()
        if domain.endswith(".example.co.uk"):
            return "example.co.uk"
        if domain.endswith(".example.com"):
            return "example.com"
        return domain

    def publicsuffix(self, domain):
        domain = domain.lower()
        if domain.endswith(".co.uk"):
            return "co.uk"
        if domain.endswith(".com"):
            return "com"
        return domain.split(".")[-1]


class TestDmarcPolicy(unittest.TestCase):
    def testStrictValidRecord(self):
        txt = "v=DMARC1; p=reject; adkim=s; aspf=r; pct=100; rua=mailto:dmarc@example.com"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertEqual(mode, "strict")
        self.assertEqual(errors, [])
        self.assertEqual(policy.p, "reject")
        self.assertEqual(policy.adkim, "s")
        self.assertEqual(policy.rua, ["mailto:dmarc@example.com"])

    def testStrictInvalidUnknownTagFallbackValid(self):
        txt = "v=DMARC1; p=quarantine; x-unknown=test; rua=mailto:dmarc@example.com"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertIsNotNone(policy)
        self.assertEqual(mode, "fallback")
        self.assertTrue(any("Unknown tag in strict mode" in error for error in errors))

    def testInvalidUnrecoverableBadVersion(self):
        txt = "v=DMARC2; p=reject"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertIsNone(policy)
        self.assertIsNone(mode)
        self.assertTrue(any("invalid v=DMARC1" in error for error in errors))

    def testIdnNormalization(self):
        normalized = parsedmarc.normalize_domain("żółć.pl")
        self.assertEqual(normalized, "xn--kda4b0koi.pl")
        self.assertTrue(
            parsedmarc.domains_equal_for_alignment("ŻÓŁĆ.pl", "xn--kda4b0koi.pl")
        )

    def testPsdDiscoveryEnabledAutoMode(self):
        records = {
            "_dmarc.mail.example.co.uk": [],
            "_dmarc.example.co.uk": [],
            "_dmarc.co.uk": ["v=DMARC1; p=reject; rua=mailto:psd@co.uk"],
        }

        def resolver(name, record_type):
            if record_type != "TXT":
                return []
            return records.get(name, [])

        policy, discovery_path, mode = parsedmarc.discover_dmarc_policy(
            "mail.example.co.uk",
            dns_resolver=resolver,
            psl_provider=_FakePSL(),
            flags={"enable_psd": True, "dmarc_strict_mode": "auto"},
        )
        self.assertIsNotNone(policy)
        self.assertEqual(policy.source, "psd")
        self.assertEqual(mode, "strict")
        self.assertEqual(
            discovery_path,
            [
                "_dmarc.mail.example.co.uk:0",
                "_dmarc.example.co.uk:0",
                "_dmarc.co.uk:1",
            ],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
