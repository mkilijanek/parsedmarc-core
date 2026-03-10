#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function, unicode_literals

import unittest
from unittest.mock import MagicMock, patch

from imapclient.exceptions import IMAPClientError

from parsedmarc.mail.imap import IMAPConnection
import parsedmarc.mail.imap as imap_module


class _BreakLoop(BaseException):
    pass


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
            mocked_client.search.assert_called_with("SINCE 2026-03-01")
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


class TestImapFallbacks(unittest.TestCase):
    def testDeleteSuccessDoesNotUseFallback(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection.delete_message(42)
        connection._client.delete_messages.assert_called_once_with([42])
        connection._client.add_flags.assert_not_called()
        connection._client.expunge.assert_not_called()

    def testDeleteFallbackUsesFlagsAndExpunge(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.delete_messages.side_effect = IMAPClientError("uid expunge")
        connection.delete_message(42)
        connection._client.add_flags.assert_called_once_with(
            [42], [r"\Deleted"], silent=True
        )
        connection._client.expunge.assert_called_once_with()

    def testDeleteFallbackErrorPropagates(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.delete_messages.side_effect = IMAPClientError("uid expunge")
        connection._client.add_flags.side_effect = IMAPClientError("flag failed")
        with self.assertRaises(IMAPClientError):
            connection.delete_message(42)

    def testMoveSuccessDoesNotUseFallback(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        with patch.object(connection, "delete_message") as delete_mock:
            connection.move_message(99, "Archive")
        connection._client.move_messages.assert_called_once_with([99], "Archive")
        connection._client.copy.assert_not_called()
        delete_mock.assert_not_called()

    def testMoveFallbackCopiesThenDeletes(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.move_messages.side_effect = IMAPClientError("move failed")
        with patch.object(connection, "delete_message") as delete_mock:
            connection.move_message(99, "Archive")
        connection._client.copy.assert_called_once_with([99], "Archive")
        delete_mock.assert_called_once_with(99)

    def testMoveFallbackCopyErrorPropagates(self):
        connection = IMAPConnection.__new__(IMAPConnection)
        connection._client = MagicMock()
        connection._client.move_messages.side_effect = IMAPClientError("move failed")
        connection._client.copy.side_effect = IMAPClientError("copy failed")
        with patch.object(connection, "delete_message") as delete_mock:
            with self.assertRaises(IMAPClientError):
                connection.move_message(99, "Archive")
        delete_mock.assert_not_called()
