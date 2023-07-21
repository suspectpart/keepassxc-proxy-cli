import base64
import json
import logging
import os
import platform
import socket
import traceback
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from time import sleep

from keepassxc_proxy_client import protocol
from keepassxc_proxy_client.protocol import ResponseUnsuccesfulException, WinNamedPipe
from tabulate import tabulate

logging.basicConfig(
    encoding='utf-8',
    level=(logging.WARNING, logging.INFO)[bool(os.getenv('DEBUG'))]
)


class ErrorCodes(IntEnum):
    ERROR_KEEPASS_DATABASE_NOT_OPENED = 1,
    ERROR_KEEPASS_DATABASE_HASH_NOT_RECEIVED = 2,
    ERROR_KEEPASS_CLIENT_PUBLIC_KEY_NOT_RECEIVED = 3,
    ERROR_KEEPASS_CANNOT_DECRYPT_MESSAGE = 4,
    ERROR_KEEPASS_TIMEOUT_OR_NOT_CONNECTED = 5,
    ERROR_KEEPASS_ACTION_CANCELLED_OR_DENIED = 6,
    ERROR_KEEPASS_CANNOT_ENCRYPT_MESSAGE = 7,
    ERROR_KEEPASS_ASSOCIATION_FAILED = 8,
    ERROR_KEEPASS_KEY_CHANGE_FAILED = 9,
    ERROR_KEEPASS_ENCRYPTION_KEY_UNRECOGNIZED = 10,
    ERROR_KEEPASS_NO_SAVED_DATABASES_FOUND = 11,
    ERROR_KEEPASS_INCORRECT_ACTION = 12,
    ERROR_KEEPASS_EMPTY_MESSAGE_RECEIVED = 13,
    ERROR_KEEPASS_NO_URL_PROVIDED = 14,
    ERROR_KEEPASS_NO_LOGINS_FOUND = 15,
    ERROR_KEEPASS_NO_GROUPS_FOUND = 16,
    ERROR_KEEPASS_CANNOT_CREATE_NEW_GROUP = 17,
    ERROR_KEEPASS_NO_VALID_UUID_PROVIDED = 18,
    ERROR_KEEPASS_ACCESS_TO_ALL_ENTRIES_DENIED = 19


def armored(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def unarmored(s: str) -> bytes:
    return base64.b64decode(s)


class AssociationsStore:
    def __init__(self, associations_file: Path):
        self._associations_file = associations_file
        self.__associations = None

    def __getitem__(self, item):
        if not self.__associations:
            self.__associations = self.__load_associations()

        return self.__associations.get(item)

    def __load_associations(self) -> dict:
        if not self._associations_file.exists():
            return {}

        logging.info(f'Loading Connection from {self._associations_file}')

        with open(self._associations_file, 'rt') as file:
            return json.load(file)

    def store_association(self, db_hash, name, public_key, version):
        logging.info(f'Storing connections in {self._associations_file}')

        self.__associations.update({
            db_hash: {
                'name': name,
                'public_key': armored(public_key),
                'version': version,
                'created': datetime.now().isoformat(),
            }
        })

        with open(self._associations_file, 'wt') as file:
            json.dump(self.__associations, file, indent=2)

    def dump_table(self):
        headers = ('DB Hash', 'Name', 'Public Key', 'KeePass Version', 'Created')

        associations = [
            (db_hash, *association.values())
            for db_hash, association in self.all().items()
        ]

        return tabulate(associations, headers=headers)

    def all(self):
        if not self.__associations:
            self.__associations = self.__load_associations()

        return self.__associations.copy()


class Connection(protocol.Connection):
    def __init__(self, associations_store: AssociationsStore):
        super().__init__()

        self.associations_store = associations_store

    def reconnect(self, test_associate=False):
        """Reconnect to Keepass UNIX Socket.

        Reconnecting opens up a fresh socket and performs a key exchange.
        If your connection has been associated before, you need to pass
        True for test_associate in order to reestablish association as well,
        otherwise requests will fail with ERROR_KEEPASS_ASSOCIATION_FAILED (8).

        Args:
            test_associate: Whether associations should be (re-)established.

        Returns:
            The connection.

        Notes:
            Untested in Windows. I just copied the socket logic from the
            base connection class, but I don't know what I am doing exactly.
        """
        self.socket.close()

        if platform.system() == "Windows":
            import win32file  # noqa
            self.socket = WinNamedPipe(
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                win32file.OPEN_EXISTING,
            )
        else:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        self.connect()

        if test_associate:
            self.test_associate(False)

        return self

    def __enter__(self):
        """Reconnect and return connection."""
        self.reconnect(test_associate=True)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close underlying socket.

        If there was an error returned by the socket, bubble it as SystemExit.
        """
        self.socket.close()

        if exc_type and exc_type == ResponseUnsuccesfulException:
            traceback.print_exc()
            exit(int(exc_val.args[0]["errorCode"]))

    @classmethod
    def bootstrap(cls, associations: AssociationsStore, wait_for_unlock: int = 30):
        db_hash = version = None
        wait_for_unlock = countdown = max(0, int(wait_for_unlock))
        trigger_unlock = wait_for_unlock > 0

        connection = cls(associations)

        while countdown >= 0:
            try:
                connection.reconnect()
                db_hash, version = connection.get_database_info(
                    trigger_unlock=trigger_unlock and countdown == wait_for_unlock
                )
                break
            except ResponseUnsuccesfulException as e:
                error_code = int(e.args[0]["errorCode"])

                if error_code != ErrorCodes.ERROR_KEEPASS_DATABASE_NOT_OPENED:
                    raise

                sleep(min(countdown, 1))
                countdown -= 1

        if association := associations[db_hash]:
            name = association["name"]
            public_key = unarmored(association["public_key"])

            connection.load_associate(name, public_key)

            logging.info(f'Reusing association {name!r}')
        else:
            connection.associate()
            name, public_key = connection.dump_associate()
            associations.store_association(db_hash, name, public_key, version)

            logging.info(f'Storing new association {name!r} ({armored(public_key)})')

        connection.test_associate(trigger_unlock)

        return connection

    def get_database_info(self, trigger_unlock=False):
        message = {
            "action": "get-databasehash",
        }
        self.send_encrypted_message(message, trigger_unlock=trigger_unlock)

        response = self.get_encrypted_response()
        return response["hash"], response["version"]

    def get_all_logins(self, url):
        msg = {
            "action": "get-logins",
            "url": url,
            "keys": [
                {
                    "id": association["name"],
                    "key": association["public_key"],
                }
                for association
                in self.associations_store.all().values()
            ]
        }

        self.send_encrypted_message(msg)
        response = self.get_encrypted_response()

        if not response["count"]:
            return False

        return response["entries"]

    def get_login_by_uuid(self, uuid: str):
        """Get single login by uuid of database entry.

        Uses magic keepassxc:// protocol.
        """
        return self.get_all_logins(f'keepassxc://by-uuid/{uuid}')[0]

    def get_logins_by_path(self, path: str):
        """Get logins by path of database entry.

        An entry path navigates to an entry by its title,
        preceded by all groups and subgroups the entry is in,
        delimited by slashes ("Root" group excluded).

        Example:
            Given a folder structure like

              Root
              ├─ Subgroup_A/
              ├─ Subgroup_B/
              │  ├─ SubSubgroup
              │  │  ├─ Entry

            The entry "Entry" would be found with a path

              Subgroup_B/SubSubgroup/Entry

        Uses magic keepassxc:// protocol.
        """
        return self.get_all_logins(f'keepassxc://by-path/{path}')
