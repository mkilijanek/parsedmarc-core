# -*- coding: utf-8 -*-

from __future__ import annotations

import mailbox
import os
from time import sleep
from typing import Dict

from parsedmarc.log import logger
from parsedmarc.mail.mailbox_connection import MailboxConnection


class MaildirConnection(MailboxConnection):
    def __init__(
        self,
        maildir_path: str,
        maildir_create: bool = False,
    ):
        self._maildir_path = maildir_path
        self._maildir_create = maildir_create
        try:
            maildir_owner = os.stat(maildir_path).st_uid
        except OSError:
            maildir_owner = None
        current_uid = os.getuid()
        if maildir_owner is not None and current_uid != maildir_owner:
            if current_uid == 0:
                try:
                    logger.warning(
                        "Switching uid to {} to access Maildir".format(maildir_owner)
                    )
                    os.setuid(maildir_owner)
                except OSError as e:
                    logger.warning(
                        "Failed to switch uid to {}: {}".format(maildir_owner, e)
                    )
            else:
                logger.warning(
                    "Runtime uid {} differs from maildir {} owner {}. "
                    "Access may fail if permissions are insufficient.".format(
                        current_uid, maildir_path, maildir_owner
                    )
                )
        if maildir_create:
            for subdir in ("cur", "new", "tmp"):
                os.makedirs(os.path.join(maildir_path, subdir), exist_ok=True)
        self._client = mailbox.Maildir(maildir_path, create=maildir_create)
        self._subfolder_client: Dict[str, mailbox.Maildir] = {}

    def create_folder(self, folder_name: str):
        self._subfolder_client[folder_name] = self._client.add_folder(folder_name)

    def fetch_messages(self, reports_folder: str, **kwargs):
        return self._client.keys()

    def fetch_message(self, message_id: str) -> str:
        msg = self._client.get(message_id)
        if msg is not None:
            msg = msg.as_string()
            if msg is not None:
                return msg
        return ""

    def delete_message(self, message_id: str):
        self._client.remove(message_id)

    def move_message(self, message_id: str, folder_name: str):
        message_data = self._client.get(message_id)
        if message_data is None:
            return
        if folder_name not in self._subfolder_client:
            self._subfolder_client[folder_name] = self._client.add_folder(folder_name)
        self._subfolder_client[folder_name].add(message_data)
        self._client.remove(message_id)

    def keepalive(self):
        return

    def watch(self, check_callback, check_timeout, config_reloading=None):
        while True:
            if config_reloading and config_reloading():
                return
            try:
                check_callback(self)
            except Exception as e:
                logger.warning("Maildir init error. {0}".format(e))
            if config_reloading and config_reloading():
                return
            sleep(check_timeout)
