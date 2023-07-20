#!/usr/bin/env python
import argparse
import base64
import json
import logging
import os
import socket
import sys
import traceback
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from time import sleep

from keepassxc_proxy_client import protocol
from keepassxc_proxy_client.protocol import ResponseUnsuccesfulException
from tabulate import tabulate

logging.basicConfig(
    encoding='utf-8',
    level=(logging.WARNING, logging.INFO)[bool(os.getenv('DEBUG'))]
)

CONNECTION_FILE = None


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

        logging.info(f'Loading Connection from {CONNECTION_FILE}')

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

    def reconnect(self):
        """Reconnect to Keepass UNIX Socket."""
        self.socket.shutdown(1)
        self.socket.close()
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connect()

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


def list_associations(**args):
    return AssociationsStore(args['associations_file']).dump_table()


def get_all_logins(**args):
    try:
        association_store = AssociationsStore(args['associations_file'])
        connection = Connection.bootstrap(
            association_store,
            wait_for_unlock=args.get('wait_for_unlock'),
        )
        credentials = connection.get_all_logins(args.get('url'))

        if len(credentials) == 1 and args.get('password_only'):
            return credentials[0]["password"]

        return json.dumps(credentials)

    except ResponseUnsuccesfulException as error:
        traceback.print_exc()
        exit(int(error.args[0]["errorCode"]))


def by_uuid(**args):
    try:
        connection = Connection.bootstrap(
            AssociationsStore(args['associations_file']),
            wait_for_unlock=args.get('wait_for_unlock'),
        )
        credentials = connection.get_login_by_uuid(args.get('uuid'))

        return credentials['password'] if args['password_only'] else credentials

    except ResponseUnsuccesfulException as error:
        traceback.print_exc()
        exit(int(error.args[0]["errorCode"]))


def by_path(**args):
    try:
        connection = Connection.bootstrap(
            AssociationsStore(args['associations_file']),
            wait_for_unlock=args.get('wait_for_unlock'),
        )
        credentials = connection.get_logins_by_path(args.get('path'))

        if len(credentials) == 1 and args.get('password_only'):
            return credentials[0]["password"]

        return json.dumps(credentials)

    except ResponseUnsuccesfulException as error:
        traceback.print_exc()
        exit(int(error.args[0]["errorCode"]))


def main(argv):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        prog='kpproxycli',
        description='CLI for Browser Proxy',
        epilog=(
            'Author: Horst Schneider <horst.schneider@urz.uni-heidelberg.de>.\n'
            'Guaranteed to **never** user cowsay in any of the output.'
        ),
    )

    parser.add_argument(
        '--wait-for-unlock',
        nargs="?",
        help="Trigger unlock database and wait n seconds for database to be unlocked",
        default=0,
        type=int,
    )

    parser.add_argument(
        '--password-only',
        help=(
            "If only one login is found, just grab the password of it.\n"
            "For more than one login, all information is returned and this\n"
            "parameter will be ignored."
        ),
        action="store_true",
    )

    parser.add_argument(
        '--associations-file',
        help=(
            "Associations file to use.\n"
            "You can store you connections to re-associate later\n."
            "Use kpproxycli ls to list all known associations."
        ),
        default=Path(os.getcwd()) / '.kee',
    )

    subparsers = parser.add_subparsers(help='sub-command help')

    # subcommand ls
    ls_parser = subparsers.add_parser('ls', help="List all known associations")
    ls_parser.set_defaults(func=list_associations)

    # subcommand uuid
    uuid_parser = subparsers.add_parser('uuid', help="Find single login by uuid")
    uuid_parser.set_defaults(func=by_uuid)
    uuid_parser.add_argument(metavar='entry_uuid', dest='uuid')

    # subcommand path
    uuid_parser = subparsers.add_parser(
        'path',
        help="Find logins by path (e.g. Group/Subgroup/SomeEntry).",
    )
    uuid_parser.set_defaults(func=by_path)
    uuid_parser.add_argument(metavar='entry_path', dest='path')

    # subcommand url
    uuid_parser = subparsers.add_parser('url', help='Find logins by URL')
    uuid_parser.set_defaults(func=get_all_logins)
    uuid_parser.add_argument(metavar='entry_uuid', dest='url')

    args = parser.parse_args(argv)

    if "func" in args:
        end = '' if args.password_only else '\n'

        print(args.func(**vars(args)), end=end)
    else:
        parser.print_help()


if __name__ == '__main__':
    main(sys.argv[1:])
