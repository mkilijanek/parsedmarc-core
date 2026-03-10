#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import os
import sys
import tempfile
import unittest
from base64 import urlsafe_b64encode
from tempfile import NamedTemporaryFile
from unittest.mock import MagicMock, patch

from googleapiclient.errors import HttpError
from httplib2 import Response

import parsedmarc.cli
from parsedmarc.mail.gmail import GmailConnection
from parsedmarc.mail.gmail import _get_creds
import parsedmarc.mail.gmail as gmail_module


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
        self.assertIn("Subject: test", content)

    def testMoveAndDeleteMessage(self):
        connection = self._build_connection()
        connection._find_label_id_for_label = MagicMock(return_value="ARCHIVE")
        messages_api = connection.service.users.return_value.messages.return_value
        messages_api.modify.return_value.execute.return_value = {}
        connection.move_message("m1", "Archive")
        messages_api.modify.assert_called_once()
        connection.delete_message("m1")
        messages_api.delete.assert_called_once_with(userId="me", id="m1")
        messages_api.delete.return_value.execute.assert_called_once()

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

    def testGetCredsRefreshesExpiredToken(self):
        expired_creds = MagicMock()
        expired_creds.valid = False
        expired_creds.expired = True
        expired_creds.refresh_token = "rt"
        expired_creds.to_json.return_value = '{"token":"refreshed"}'

        with NamedTemporaryFile("w", delete=False) as token_file:
            token_file.write("{}")
            token_path = token_file.name
        try:
            with patch.object(
                gmail_module.Credentials,
                "from_authorized_user_file",
                return_value=expired_creds,
            ):
                returned = _get_creds(
                    token_path, "credentials.json", ["scope"], 8080
                )
        finally:
            os.remove(token_path)

        self.assertEqual(returned, expired_creds)
        expired_creds.refresh.assert_called_once()

    def testCreateFolderConflictIgnored(self):
        connection = self._build_connection()
        labels_api = connection.service.users.return_value.labels.return_value
        conflict = HttpError(Response({"status": "409"}), b"conflict")
        labels_api.create.return_value.execute.side_effect = conflict
        connection.create_folder("Existing")


class TestGmailAuthModes(unittest.TestCase):
    @patch("parsedmarc.mail.gmail.service_account.Credentials.from_service_account_file")
    def testGetCredsServiceAccountWithoutSubject(self, mock_from_service_account_file):
        service_creds = MagicMock()
        service_creds.with_subject.return_value = MagicMock()
        mock_from_service_account_file.return_value = service_creds

        creds = gmail_module._get_creds(
            token_file=".token",
            credentials_file="service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            oauth2_port=8080,
            auth_mode="service_account",
            service_account_user=None,
        )

        self.assertIs(creds, service_creds)
        mock_from_service_account_file.assert_called_once_with(
            "service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        )
        service_creds.with_subject.assert_not_called()

    @patch("parsedmarc.mail.gmail.service_account.Credentials.from_service_account_file")
    def testGetCredsServiceAccountWithSubject(self, mock_from_service_account_file):
        base_creds = MagicMock()
        delegated_creds = MagicMock()
        base_creds.with_subject.return_value = delegated_creds
        mock_from_service_account_file.return_value = base_creds

        creds = gmail_module._get_creds(
            token_file=".token",
            credentials_file="service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            oauth2_port=8080,
            auth_mode="service_account",
            service_account_user="dmarc@example.com",
        )

        self.assertIs(creds, delegated_creds)
        base_creds.with_subject.assert_called_once_with("dmarc@example.com")

    def testGetCredsRejectsUnsupportedAuthMode(self):
        with self.assertRaises(ValueError):
            gmail_module._get_creds(
                token_file=".token",
                credentials_file="client-secret.json",
                scopes=["https://www.googleapis.com/auth/gmail.modify"],
                oauth2_port=8080,
                auth_mode="unsupported",
            )

    @patch("parsedmarc.mail.gmail.Path.exists", return_value=True)
    @patch("parsedmarc.mail.gmail.Credentials.from_authorized_user_file")
    def testGetCredsInstalledAppStillUsesTokenFile(
        self, mock_from_authorized_user_file, _mock_exists
    ):
        token_creds = MagicMock()
        token_creds.valid = True
        mock_from_authorized_user_file.return_value = token_creds

        creds = gmail_module._get_creds(
            token_file=".token",
            credentials_file="client-secret.json",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            oauth2_port=8080,
            auth_mode="installed_app",
        )

        self.assertIs(creds, token_creds)
        mock_from_authorized_user_file.assert_called_once_with(
            ".token",
            ["https://www.googleapis.com/auth/gmail.modify"],
        )

    @patch("parsedmarc.mail.gmail.GmailConnection._find_label_id_for_label")
    @patch("parsedmarc.mail.gmail.build")
    @patch("parsedmarc.mail.gmail._get_creds")
    def testGmailConnectionPassesAuthModeAndDelegatedUser(
        self, mock_get_creds, mock_build, mock_find_label
    ):
        mock_get_creds.return_value = MagicMock()
        mock_build.return_value = MagicMock()
        mock_find_label.return_value = "INBOX"

        gmail_module.GmailConnection(
            token_file=".token",
            credentials_file="service-account.json",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            include_spam_trash=False,
            reports_folder="INBOX",
            oauth2_port=8080,
            paginate_messages=True,
            auth_mode="service_account",
            service_account_user="dmarc@example.com",
        )

        mock_get_creds.assert_called_once_with(
            ".token",
            "service-account.json",
            ["https://www.googleapis.com/auth/gmail.modify"],
            8080,
            auth_mode="service_account",
            service_account_user="dmarc@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.GmailConnection")
    def testCliPassesGmailServiceAccountAuthSettings(
        self, mock_gmail_connection, mock_get_mailbox_reports
    ):
        mock_gmail_connection.return_value = MagicMock()
        mock_get_mailbox_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        config = """[general]
silent = true

[gmail_api]
credentials_file = /tmp/service-account.json
auth_mode = service_account
service_account_user = dmarc@example.com
scopes = https://www.googleapis.com/auth/gmail.modify
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg_file:
            cfg_file.write(config)
            config_path = cfg_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("auth_mode"), "service_account"
        )
        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("service_account_user"),
            "dmarc@example.com",
        )

    @patch("parsedmarc.cli.get_dmarc_reports_from_mailbox")
    @patch("parsedmarc.cli.GmailConnection")
    def testCliAcceptsDelegatedUserAlias(self, mock_gmail_connection, mock_get_reports):
        mock_gmail_connection.return_value = MagicMock()
        mock_get_reports.return_value = {
            "aggregate_reports": [],
            "forensic_reports": [],
            "smtp_tls_reports": [],
        }
        config = """[general]
silent = true

[gmail_api]
credentials_file = /tmp/service-account.json
auth_mode = service_account
delegated_user = delegated@example.com
scopes = https://www.googleapis.com/auth/gmail.modify
"""
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as cfg_file:
            cfg_file.write(config)
            config_path = cfg_file.name
        self.addCleanup(lambda: os.path.exists(config_path) and os.remove(config_path))

        with patch.object(sys, "argv", ["parsedmarc", "-c", config_path]):
            parsedmarc.cli._main()

        self.assertEqual(
            mock_gmail_connection.call_args.kwargs.get("service_account_user"),
            "delegated@example.com",
        )
