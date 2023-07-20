#!/usr/bin/env python
import argparse
import json
import os
import sys
import traceback
from pathlib import Path

from keepassxc_proxy_client.protocol import ResponseUnsuccesfulException

from lib import AssociationsStore, Connection


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
        default=Path(os.getcwd()) / '.keepassxc_associations',
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
