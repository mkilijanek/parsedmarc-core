#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import os
import sys
import tempfile
import unittest
from base64 import urlsafe_b64encode
from glob import glob
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import patch
from unittest.mock import MagicMock

from lxml import etree
from googleapiclient.errors import HttpError
from httplib2 import Response
from imapclient.exceptions import IMAPClientError

import parsedmarc
import parsedmarc.cli
from parsedmarc.mail.graph import MSGraphConnection
from parsedmarc.mail.gmail import GmailConnection
from parsedmarc.mail.gmail import _get_creds
from parsedmarc.mail.graph import _get_cache_args
from parsedmarc.mail.graph import _generate_credential
from parsedmarc.mail.graph import _load_token
from parsedmarc.mail.imap import IMAPConnection
import parsedmarc.mail.gmail as gmail_module
import parsedmarc.mail.graph as graph_module
import parsedmarc.mail.imap as imap_module
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

    def testStrictInvalidDuplicateTagFallbackValid(self):
        txt = "v=DMARC1; p=none; p=reject; rua=mailto:dmarc@example.com"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertIsNotNone(policy)
        self.assertEqual(mode, "fallback")
        self.assertEqual(policy.p, "none")
        self.assertTrue(any("Duplicate tag in strict mode" in error for error in errors))

    def testStrictInvalidVNotFirstFallbackValid(self):
        txt = "p=none; v=DMARC1; rua=mailto:dmarc@example.com"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertIsNotNone(policy)
        self.assertEqual(mode, "fallback")
        self.assertTrue(any("v=DMARC1 must be first tag" in error for error in errors))

    def testInvalidUnrecoverableBadVersion(self):
        txt = "v=DMARC2; p=reject"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertIsNone(policy)
        self.assertIsNone(mode)
        self.assertTrue(any("invalid v=DMARC1" in error for error in errors))

    def testInvalidUnrecoverablePctOutOfRange(self):
        txt = "v=DMARC1; p=reject; pct=101"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertIsNone(policy)
        self.assertIsNone(mode)
        self.assertTrue(any("pct must be in range 0..100" in error for error in errors))

    def testInvalidUnrecoverableMalformedRua(self):
        txt = "v=DMARC1; p=reject; rua=https://example.com/report"
        policy, mode, errors = parsedmarc.parse_dmarc_record(txt, domain="example.com")
        self.assertIsNone(policy)
        self.assertIsNone(mode)
        self.assertTrue(any("Malformed URI" in error for error in errors))

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

    def testPsdIgnoredInLegacyMode(self):
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
            flags={"enable_psd": True, "dmarc_strict_mode": "legacy"},
        )
        self.assertIsNone(policy)
        self.assertIsNone(mode)
        self.assertEqual(
            discovery_path,
            ["_dmarc.mail.example.co.uk:0", "_dmarc.example.co.uk:0"],
        )


class _FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _FakeGraphClient:
    def get(self, url, params=None):
        if "/mailFolders/inbox?$select=id,displayName" in url:
            return _FakeResponse(200, {"id": "inbox-id", "displayName": "Inbox"})

        if "/mailFolders?$filter=displayName eq 'Inbox'" in url:
            return _FakeResponse(
                404,
                {
                    "error": {
                        "code": "ErrorItemNotFound",
                        "message": "Default folder Root not found.",
                    }
                },
            )

        if "/mailFolders?$filter=displayName eq 'Custom'" in url:
            return _FakeResponse(
                404,
                {
                    "error": {
                        "code": "ErrorItemNotFound",
                        "message": "Default folder Root not found.",
                    }
                },
            )
        return _FakeResponse(404, {"error": {"code": "NotFound"}})


class _DummyMailboxConnection:
    def __init__(self):
        self.fetch_calls = []

    def create_folder(self, folder_name):
        return None

    def fetch_messages(self, reports_folder, **kwargs):
        self.fetch_calls.append({"reports_folder": reports_folder, **kwargs})
        return []

    def fetch_message(self, message_id, **kwargs):
        return ""

    def delete_message(self, message_id):
        return None

    def move_message(self, message_id, folder_name):
        return None

    def keepalive(self):
        return None

    def watch(self, check_callback, check_timeout):
        return None


class TestIssueFixes(unittest.TestCase):
    def testMsGraphWellKnownFolderFallback(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._client = _FakeGraphClient()

        folder_id = connection._find_folder_id_from_folder_path("Inbox")
        self.assertEqual(folder_id, "inbox-id")

    def testMsGraphUnknownFolderStillFails(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._client = _FakeGraphClient()

        with self.assertRaises(RuntimeWarning):
            connection._find_folder_id_from_folder_path("Custom")

    def testMailboxBatchModeAvoidsExtraFullFetch(self):
        connection = _DummyMailboxConnection()
        parsedmarc.get_dmarc_reports_from_mailbox(
            connection=connection,
            reports_folder="INBOX",
            test=True,
            batch_size=10,
            create_folders=False,
        )
        self.assertEqual(len(connection.fetch_calls), 1)

    def testCliFailOnOutputErrorExitsNonZero(self):
        sample_paths = sorted(glob("samples/aggregate/*.xml"))
        self.assertTrue(len(sample_paths) > 0)
        sample_path = sample_paths[0]

        config_text = """
[general]
silent = True
offline = True
always_use_local_files = True
save_aggregate = True
fail_on_output_error = True

[webhook]
aggregate_url = http://127.0.0.1:9
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg_file:
            cfg_file.write(config_text)
            cfg_path = cfg_file.name

        try:
            with patch.object(
                sys,
                "argv",
                ["parsedmarc", "-c", cfg_path, sample_path],
            ):
                with patch.object(
                    parsedmarc.cli.webhook.WebhookClient,
                    "save_aggregate_report_to_webhook",
                    side_effect=RuntimeError("webhook send failed"),
                ):
                    with self.assertRaises(SystemExit) as system_exit:
                        parsedmarc.cli._main()
            self.assertEqual(system_exit.exception.code, 1)
        finally:
            os.remove(cfg_path)


class _FakeGraphResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class _BreakLoop(BaseException):
    pass


class TestGmailConnection(unittest.TestCase):
    def _build_connection(self, *, paginate=True):
        connection = GmailConnection.__new__(GmailConnection)
        connection.include_spam_trash = False
        connection.reports_label_id = "REPORTS"
        connection.paginate_messages = paginate
        connection.service = MagicMock()
        return connection

    def testFindLabelId(self):
        connection = self._build_connection()
        labels_api = connection.service.users.return_value.labels.return_value
        labels_api.list.return_value.execute.return_value = {
            "labels": [
                {"id": "INBOX", "name": "INBOX"},
                {"id": "REPORTS", "name": "Reports"},
            ]
        }
        self.assertEqual(connection._find_label_id_for_label("Reports"), "REPORTS")
        self.assertEqual(connection._find_label_id_for_label("MISSING"), "")

    def testFetchMessagesWithPagination(self):
        connection = self._build_connection(paginate=True)
        messages_api = connection.service.users.return_value.messages.return_value

        def list_side_effect(**kwargs):
            response = MagicMock()
            if kwargs.get("pageToken") is None:
                response.execute.return_value = {
                    "messages": [{"id": "a"}, {"id": "b"}],
                    "nextPageToken": "n1",
                }
            else:
                response.execute.return_value = {"messages": [{"id": "c"}]}
            return response

        messages_api.list.side_effect = list_side_effect
        connection._find_label_id_for_label = MagicMock(return_value="REPORTS")
        self.assertEqual(connection.fetch_messages("Reports"), ["a", "b", "c"])

    def testFetchMessageDecoding(self):
        connection = self._build_connection()
        messages_api = connection.service.users.return_value.messages.return_value
        raw = urlsafe_b64encode(b"Subject: test\n\nbody").decode()
        messages_api.get.return_value.execute.return_value = {"raw": raw}
        content = connection.fetch_message("m1")
        self.assertIn(b"Subject: test", content)

    def testMoveAndDeleteMessage(self):
        connection = self._build_connection()
        connection._find_label_id_for_label = MagicMock(return_value="ARCHIVE")
        messages_api = connection.service.users.return_value.messages.return_value
        messages_api.modify.return_value.execute.return_value = {}
        connection.move_message("m1", "Archive")
        messages_api.modify.assert_called_once()
        connection.delete_message("m1")
        messages_api.delete.assert_called_once_with(userId="me", id="m1")

    def testGetCredsFromTokenFile(self):
        creds = MagicMock()
        creds.valid = True
        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("{}")
            token_path = token_file.name
        try:
            with patch.object(
                gmail_module.Credentials,
                "from_authorized_user_file",
                return_value=creds,
            ):
                returned = _get_creds(
                    token_path, "credentials.json", ["scope"], 8080
                )
        finally:
            os.remove(token_path)
        self.assertEqual(returned, creds)

    def testGetCredsWithOauthFlow(self):
        expired_creds = MagicMock()
        expired_creds.valid = False
        expired_creds.expired = False
        expired_creds.refresh_token = None
        new_creds = MagicMock()
        new_creds.valid = True
        new_creds.to_json.return_value = '{"token":"x"}'
        flow = MagicMock()
        flow.run_local_server.return_value = new_creds

        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("{}")
            token_path = token_file.name
        try:
            with patch.object(
                gmail_module.Credentials,
                "from_authorized_user_file",
                return_value=expired_creds,
            ):
                with patch.object(
                    gmail_module.InstalledAppFlow,
                    "from_client_secrets_file",
                    return_value=flow,
                ):
                    returned = _get_creds(
                        token_path, "credentials.json", ["scope"], 8080
                    )
        finally:
            os.remove(token_path)
        self.assertEqual(returned, new_creds)
        flow.run_local_server.assert_called_once()

    def testCreateFolderConflictIgnored(self):
        connection = self._build_connection()
        labels_api = connection.service.users.return_value.labels.return_value
        conflict = HttpError(Response({"status": "409"}), b"conflict")
        labels_api.create.return_value.execute.side_effect = conflict
        connection.create_folder("Existing")


class TestGraphConnection(unittest.TestCase):
    def testLoadTokenMissing(self):
        self.assertIsNone(_load_token(Path("/tmp/definitely_missing_token_file")))

    def testLoadTokenExisting(self):
        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("serialized-auth-record")
            token_path = token_file.name
        try:
            self.assertEqual(_load_token(Path(token_path)), "serialized-auth-record")
        finally:
            os.remove(token_path)

    def testGetAllMessagesPagination(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        first_response = _FakeGraphResponse(
            200, {"value": [{"id": "1"}], "@odata.nextLink": "next-url"}
        )
        second_response = _FakeGraphResponse(200, {"value": [{"id": "2"}]})
        connection._client = MagicMock()
        connection._client.get.side_effect = [first_response, second_response]
        messages = connection._get_all_messages("/url", batch_size=0, since=None)
        self.assertEqual([msg["id"] for msg in messages], ["1", "2"])

    def testFetchMessageMarksRead(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(200, text="email-content")
        connection.mark_message_read = MagicMock()
        content = connection.fetch_message("123", mark_read=True)
        self.assertEqual(content, "email-content")
        connection.mark_message_read.assert_called_once_with("123")

    def testFindFolderIdNotFound(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(200, {"value": []})
        with self.assertRaises(RuntimeError):
            connection._find_folder_id_with_parent("Missing", None)

    def testGetCacheArgsWithAuthRecord(self):
        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("serialized")
            token_path = Path(token_file.name)
        try:
            with patch.object(
                graph_module.AuthenticationRecord,
                "deserialize",
                return_value="auth_record",
            ):
                args = _get_cache_args(token_path, allow_unencrypted_storage=False)
            self.assertIn("authentication_record", args)
        finally:
            os.remove(token_path)

    def testGenerateCredentialInvalid(self):
        with self.assertRaises(RuntimeError):
            _generate_credential(
                "Nope",
                Path("/tmp/token"),
                client_id="x",
                client_secret="y",
                username="u",
                password="p",
                tenant_id="t",
                allow_unencrypted_storage=False,
            )

    def testGenerateCredentialDeviceCode(self):
        fake_credential = object()
        with patch.object(graph_module, "_get_cache_args", return_value={"cached": True}):
            with patch.object(
                graph_module,
                "DeviceCodeCredential",
                return_value=fake_credential,
            ) as mocked:
                result = _generate_credential(
                    graph_module.AuthMethod.DeviceCode.name,
                    Path("/tmp/token"),
                    client_id="cid",
                    client_secret="secret",
                    username="user",
                    password="pass",
                    tenant_id="tenant",
                    allow_unencrypted_storage=True,
                )
        self.assertIs(result, fake_credential)
        mocked.assert_called_once()

    def testGenerateCredentialUsernamePassword(self):
        fake_credential = object()
        with patch.object(graph_module, "_get_cache_args", return_value={"cached": True}):
            with patch.object(
                graph_module,
                "UsernamePasswordCredential",
                return_value=fake_credential,
            ) as mocked:
                result = _generate_credential(
                    graph_module.AuthMethod.UsernamePassword.name,
                    Path("/tmp/token"),
                    client_id="cid",
                    client_secret="secret",
                    username="user",
                    password="pass",
                    tenant_id="tenant",
                    allow_unencrypted_storage=False,
                )
        self.assertIs(result, fake_credential)
        mocked.assert_called_once()

    def testGenerateCredentialClientSecret(self):
        fake_credential = object()
        with patch.object(
            graph_module, "ClientSecretCredential", return_value=fake_credential
        ) as mocked:
            result = _generate_credential(
                graph_module.AuthMethod.ClientSecret.name,
                Path("/tmp/token"),
                client_id="cid",
                client_secret="secret",
                username="user",
                password="pass",
                tenant_id="tenant",
                allow_unencrypted_storage=False,
            )
        self.assertIs(result, fake_credential)
        mocked.assert_called_once_with(
            client_id="cid", tenant_id="tenant", client_secret="secret"
        )

    def testInitUsesSharedMailboxScopes(self):
        class FakeCredential:
            def __init__(self):
                self.authenticate = MagicMock(return_value="auth-record")

        fake_credential = FakeCredential()
        with patch.object(
            graph_module, "_generate_credential", return_value=fake_credential
        ):
            with patch.object(graph_module, "_cache_auth_record") as cache_auth:
                with patch.object(graph_module, "GraphClient") as graph_client:
                    MSGraphConnection(
                        auth_method=graph_module.AuthMethod.DeviceCode.name,
                        mailbox="shared@example.com",
                        graph_url="https://graph.microsoft.com",
                        client_id="cid",
                        client_secret="secret",
                        username="owner@example.com",
                        password="pass",
                        tenant_id="tenant",
                        token_file="/tmp/token-file",
                        allow_unencrypted_storage=True,
                    )
        fake_credential.authenticate.assert_called_once_with(
            scopes=["Mail.ReadWrite.Shared"]
        )
        cache_auth.assert_called_once()
        graph_client.assert_called_once()
        self.assertEqual(
            graph_client.call_args.kwargs.get("scopes"), ["Mail.ReadWrite.Shared"]
        )

    def testInitClientSecretSkipsAuthenticate(self):
        class FakeClientSecretCredential:
            pass

        fake_credential = FakeClientSecretCredential()
        with patch.object(
            graph_module, "ClientSecretCredential", FakeClientSecretCredential
        ):
            with patch.object(
                graph_module, "_generate_credential", return_value=fake_credential
            ):
                with patch.object(graph_module, "_cache_auth_record") as cache_auth:
                    with patch.object(graph_module, "GraphClient") as graph_client:
                        MSGraphConnection(
                            auth_method=graph_module.AuthMethod.ClientSecret.name,
                            mailbox="mailbox@example.com",
                            graph_url="https://graph.microsoft.com",
                            client_id="cid",
                            client_secret="secret",
                            username="mailbox@example.com",
                            password="pass",
                            tenant_id="tenant",
                            token_file="/tmp/token-file",
                            allow_unencrypted_storage=True,
                        )
        cache_auth.assert_not_called()
        self.assertNotIn("scopes", graph_client.call_args.kwargs)

    def testCreateFolderAndMoveErrors(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.post.return_value = _FakeGraphResponse(500, {"error": "x"})
        connection._find_folder_id_from_folder_path = MagicMock(return_value="dest")
        with self.assertRaises(RuntimeWarning):
            connection.move_message("m1", "Archive")

        connection._client.post.return_value = _FakeGraphResponse(409, {})
        connection.create_folder("Archive")

    def testCreateFolderSubfolderSuccess(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.post.return_value = _FakeGraphResponse(201, {})
        connection._find_folder_id_with_parent = MagicMock(side_effect=["parent-id"])
        connection.create_folder("Parent/Child")
        connection._find_folder_id_with_parent.assert_called_once_with("Parent", None)
        connection._client.post.assert_called_once_with(
            "/users/mailbox@example.com/mailFolders/parent-id/childFolders",
            json={"displayName": "Child"},
        )

    def testMarkReadDeleteFailures(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.patch.return_value = _FakeGraphResponse(500, {"error": "x"})
        with self.assertRaises(RuntimeWarning):
            connection.mark_message_read("m1")

        connection._client.delete.return_value = _FakeGraphResponse(500, {"error": "x"})
        with self.assertRaises(RuntimeWarning):
            connection.delete_message("m1")

    def testFetchMessagesNormalizesDefaults(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._find_folder_id_from_folder_path = MagicMock(return_value="folder-id")
        connection._get_all_messages = MagicMock(return_value=[{"id": "1"}])
        message_ids = connection.fetch_messages("Inbox")
        self.assertEqual(message_ids, ["1"])
        connection._get_all_messages.assert_called_once_with(
            "/users/mailbox@example.com/mailFolders/folder-id/messages", 0, None
        )

    def testGetAllMessagesInitialRequestFailure(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(500, text="boom")
        with self.assertRaises(RuntimeError):
            connection._get_all_messages("/url", batch_size=5, since=None)

    def testGetAllMessagesNextPageFailure(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        first_response = _FakeGraphResponse(
            200, {"value": [{"id": "1"}], "@odata.nextLink": "next-url"}
        )
        second_response = _FakeGraphResponse(500, text="boom")
        connection._client = MagicMock()
        connection._client.get.side_effect = [first_response, second_response]
        with self.assertRaises(RuntimeError):
            connection._get_all_messages("/url", batch_size=0, since=None)

    def testFindFolderIdWithParentFallsBackToWellKnown(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(500, {"error": "x"})
        connection._get_well_known_folder_id = MagicMock(return_value="inbox-id")
        self.assertEqual(
            connection._find_folder_id_with_parent("Inbox", None), "inbox-id"
        )

    def testFindFolderIdWithParentListFailure(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(500, {"error": "x"})
        with self.assertRaises(RuntimeWarning):
            connection._find_folder_id_with_parent("Child", "parent-id")

    def testFindFolderIdFromFolderPathNested(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._find_folder_id_with_parent = MagicMock(
            side_effect=["first-id", "second-id"]
        )
        folder_id = connection._find_folder_id_from_folder_path("A/B")
        self.assertEqual(folder_id, "second-id")
        self.assertEqual(connection._find_folder_id_with_parent.call_count, 2)

    def testGetWellKnownFolderIdPaths(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        self.assertIsNone(connection._get_well_known_folder_id("Not-Alias"))
        connection._client.get.return_value = _FakeGraphResponse(404, {})
        self.assertIsNone(connection._get_well_known_folder_id("Inbox"))
        connection._client.get.return_value = _FakeGraphResponse(200, {"id": "x"})
        self.assertEqual(connection._get_well_known_folder_id("Inbox"), "x")

    def testWatchRunsCallback(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        callback = MagicMock()
        with patch.object(
            graph_module, "sleep", side_effect=[None, _BreakLoop("stop")]
        ):
            with self.assertRaises(_BreakLoop):
                connection.watch(callback, check_timeout=1)
        callback.assert_called_once_with(connection)


class TestImapConnection(unittest.TestCase):
    def testDelegatesToImapClient(self):
        with patch.object(imap_module, "IMAPClient") as mocked_client_cls:
            mocked_client = MagicMock()
            mocked_client_cls.return_value = mocked_client
            connection = IMAPConnection(
                "imap.example.com", user="user", password="pass"
            )

            connection.create_folder("Archive")
            mocked_client.create_folder.assert_called_once_with("Archive")

            mocked_client.search.return_value = [1, 2]
            self.assertEqual(connection.fetch_messages("INBOX"), [1, 2])
            mocked_client.select_folder.assert_called_with("INBOX")

            connection.fetch_messages("INBOX", since="2026-03-01")
            mocked_client.search.assert_called_with(["SINCE", "2026-03-01"])

            mocked_client.fetch_message.return_value = "raw-message"
            self.assertEqual(connection.fetch_message(1), "raw-message")

            connection.delete_message(7)
            mocked_client.delete_messages.assert_called_once_with([7])

            connection.move_message(8, "Archive")
            mocked_client.move_messages.assert_called_once_with([8], "Archive")

            connection.keepalive()
            mocked_client.noop.assert_called_once()

    def testWatchReconnectPath(self):
        with patch.object(imap_module, "IMAPClient") as mocked_client_cls:
            base_client = MagicMock()
            base_client.host = "imap.example.com"
            base_client.port = 993
            base_client.ssl = True
            mocked_client_cls.return_value = base_client
            connection = IMAPConnection(
                "imap.example.com", user="user", password="pass"
            )

            calls = {"count": 0}

            def fake_imap_constructor(*args, **kwargs):
                idle_callback = kwargs.get("idle_callback")
                if calls["count"] == 0:
                    calls["count"] += 1
                    raise IMAPClientError("timeout")
                if idle_callback is not None:
                    idle_callback(base_client)
                raise _BreakLoop()

            callback = MagicMock()
            with patch.object(imap_module, "sleep", return_value=None):
                with patch.object(
                    imap_module, "IMAPClient", side_effect=fake_imap_constructor
                ):
                    with self.assertRaises(_BreakLoop):
                        connection.watch(callback, check_timeout=1)
            callback.assert_called_once_with(connection)


if __name__ == "__main__":
    unittest.main(verbosity=2)
