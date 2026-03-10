#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from unittest.mock import MagicMock, patch

from parsedmarc.mail.graph import MSGraphConnection
from parsedmarc.mail.graph import _generate_credential
from parsedmarc.mail.graph import _get_cache_args
from parsedmarc.mail.graph import _load_token
import parsedmarc.mail.graph as graph_module


class _FakeGraphResponse:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class _FakeGraphClient:
    def get(self, url, params=None):
        if "/mailFolders/inbox?$select=id,displayName" in url:
            return _FakeGraphResponse(200, {"id": "inbox-id", "displayName": "Inbox"})

        if "/mailFolders?$filter=displayName eq 'Inbox'" in url:
            return _FakeGraphResponse(
                404,
                {
                    "error": {
                        "code": "ErrorItemNotFound",
                        "message": "Default folder Root not found.",
                    }
                },
            )

        if "/mailFolders?$filter=displayName eq 'Custom'" in url:
            return _FakeGraphResponse(
                404,
                {
                    "error": {
                        "code": "ErrorItemNotFound",
                        "message": "Default folder Root not found.",
                    }
                },
            )

        return _FakeGraphResponse(404, {"error": {"code": "NotFound"}})


class TestGraphConnection(unittest.TestCase):
    def testLoadTokenMissing(self):
        with TemporaryDirectory() as temp_dir:
            missing_path = Path(temp_dir) / "missing-token-file"
            self.assertIsNone(_load_token(missing_path))

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

    def testGetAllMessagesInitialRequestFailure(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(500, text="boom")
        with self.assertRaises(RuntimeError):
            connection._get_all_messages("/url", batch_size=0, since=None)

    def testGetAllMessagesRetriesTransientRequestErrors(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection._client = MagicMock()
        connection._client.get.side_effect = [
            graph_module.RequestException("connection reset"),
            _FakeGraphResponse(200, {"value": [{"id": "1"}]}),
        ]
        with patch.object(graph_module, "sleep") as mocked_sleep:
            messages = connection._get_all_messages("/url", batch_size=0, since=None)
        self.assertEqual([msg["id"] for msg in messages], ["1"])
        mocked_sleep.assert_called_once_with(
            graph_module.GRAPH_REQUEST_RETRY_DELAY_SECONDS
        )

    def testGetAllMessagesRaisesAfterRetryExhaustion(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection._client = MagicMock()
        connection._client.get.side_effect = graph_module.RequestException(
            "connection reset"
        )
        with patch.object(graph_module, "sleep") as mocked_sleep:
            with self.assertRaises(graph_module.RequestException):
                connection._get_all_messages("/url", batch_size=0, since=None)
        self.assertEqual(
            mocked_sleep.call_count, graph_module.GRAPH_REQUEST_RETRY_ATTEMPTS - 1
        )

    def testGetAllMessagesNextPageFailure(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        first_response = _FakeGraphResponse(
            200, {"value": [{"id": "1"}], "@odata.nextLink": "next-url"}
        )
        second_response = _FakeGraphResponse(500, text="page-fail")
        connection._client = MagicMock()
        connection._client.get.side_effect = [first_response, second_response]
        with self.assertRaises(RuntimeError):
            connection._get_all_messages("/url", batch_size=0, since=None)

    def testGetAllMessagesHonorsBatchSizeLimit(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        first_response = _FakeGraphResponse(
            200,
            {
                "value": [{"id": "1"}, {"id": "2"}],
                "@odata.nextLink": "next-url",
            },
        )
        connection._client = MagicMock()
        connection._client.get.return_value = first_response
        messages = connection._get_all_messages("/url", batch_size=2, since=None)
        self.assertEqual([msg["id"] for msg in messages], ["1", "2"])
        connection._client.get.assert_called_once()

    def testFetchMessagesPassesSinceAndBatchSize(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._find_folder_id_from_folder_path = MagicMock(return_value="folder-id")
        connection._get_all_messages = MagicMock(return_value=[{"id": "1"}])
        self.assertEqual(
            connection.fetch_messages("Inbox", since="2026-03-01", batch_size=5), ["1"]
        )
        connection._get_all_messages.assert_called_once_with(
            "/users/mailbox@example.com/mailFolders/folder-id/messages",
            5,
            "2026-03-01",
        )

    def testFetchMessageMarksRead(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "mailbox@example.com"
        connection._client = MagicMock()
        connection._client.get.return_value = _FakeGraphResponse(
            200, text="email-content"
        )
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

    def testGenerateCredentialCertificate(self):
        fake_credential = object()
        with patch.object(
            graph_module, "CertificateCredential", return_value=fake_credential
        ) as mocked:
            result = _generate_credential(
                graph_module.AuthMethod.Certificate.name,
                Path("/tmp/token"),
                client_id="cid",
                client_secret="secret",
                certificate_path="/tmp/cert.pem",
                certificate_password="secret-pass",
                username="user",
                password="pass",
                tenant_id="tenant",
                allow_unencrypted_storage=False,
            )
        self.assertIs(result, fake_credential)
        mocked.assert_called_once_with(
            client_id="cid",
            tenant_id="tenant",
            certificate_path="/tmp/cert.pem",
            password="secret-pass",
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

    def testInitCertificateAuthSkipsInteractiveAuthenticate(self):
        class DummyCertificateCredential:
            pass

        fake_credential = DummyCertificateCredential()
        with patch.object(graph_module, "CertificateCredential", DummyCertificateCredential):
            with patch.object(
                graph_module, "_generate_credential", return_value=fake_credential
            ):
                with patch.object(graph_module, "_cache_auth_record") as cache_auth:
                    with patch.object(graph_module, "GraphClient") as graph_client:
                        MSGraphConnection(
                            auth_method=graph_module.AuthMethod.Certificate.name,
                            mailbox="shared@example.com",
                            graph_url="https://graph.microsoft.com",
                            client_id="cid",
                            client_secret=None,
                            certificate_path="/tmp/cert.pem",
                            certificate_password="secret-pass",
                            username=None,
                            password=None,
                            tenant_id="tenant",
                            token_file="/tmp/token-file",
                            allow_unencrypted_storage=False,
                        )
        cache_auth.assert_not_called()
        graph_client.assert_called_once()
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


class TestMSGraphFolderFallback(unittest.TestCase):
    def testWellKnownFolderFallback(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._client = _FakeGraphClient()

        folder_id = connection._find_folder_id_from_folder_path("Inbox")
        self.assertEqual(folder_id, "inbox-id")

    def testUnknownFolderStillFails(self):
        connection = MSGraphConnection.__new__(MSGraphConnection)
        connection.mailbox_name = "shared@example.com"
        connection._client = _FakeGraphClient()

        with self.assertRaises(RuntimeWarning):
            connection._find_folder_id_from_folder_path("Custom")
