#!/usr/bin/env python
import argparse
import functools
import json
import os
import sys
from pathlib import Path

from keepassxc_proxy_cli.lib import AssociationsStore, Connection


def with_keepass_connection(func):
    """Wraps a function to inject a bootstrapped connection context."""

    @functools.wraps(func)
    def wrapper(args):
        associations = AssociationsStore(args.associations_file)

        with Connection.bootstrap(associations, args.wait_for_unlock) as connection:
            return func(connection, args)

    return wrapper


def filter_json(func):
    """Runs dicts returned by func through json.dumps()."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        return result if isinstance(result, str) else json.dumps(result)

    return wrapper


def filter_single_password(func):
    """Wherever applicable, just return a single password if requested."""

    @functools.wraps(func)
    def wrapper(connection, args):
        credentials = func(connection, args)

        if len(credentials) == 1 and args.password_only:
            return credentials[0]["password"]

        return credentials

    return wrapper


def list_associations(args):
    return AssociationsStore(args.associations_file).dump_table()


@with_keepass_connection
@filter_single_password
@filter_json
def get_all_logins(connection, args):
    return connection.get_all_logins(args.url)


@with_keepass_connection
@filter_single_password
@filter_json
def by_uuid(connection, args):
    return connection.get_logins_by_uuid(args.uuid)


@with_keepass_connection
@filter_single_password
@filter_json
def by_path(connection, args):
    return connection.get_logins_by_path(args.path)


def main():
    argv = sys.argv[1:]

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

        print(args.func(args), end=end)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
