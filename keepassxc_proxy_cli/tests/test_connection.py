import unittest
from pathlib import Path

from keepassxc_proxy_client.protocol import ResponseUnsuccesfulException

from keepassxc_proxy_cli.lib import AssociationsStore, Connection


class ConnectionTests(unittest.TestCase):
    """Make sure test_database.kdbx is unlocked and focused for tests to succeed."""

    def setUp(self):
        self.associations_store = AssociationsStore(
            Path(__file__).with_name('.keepassxc_associations')
        )
        self.database_hash = (
            "bad5cf94a40e1c36975c9d31dfc6098cad6eeefa53cf23f5ddf3ec00b1b4a26d"
        )

    def assertIsClosed(self, socket):
        """Assert that socket is closed.

        Pretty sure this does not work in Windows :/.
        """
        self.assertEqual(socket.fileno(), -1)
        self.assertTrue(socket._closed)

    def assertIsOpen(self, socket):
        """Assert that socket is open.

        Pretty sure this does not work in Windows :/.
        """
        self.assertEqual(socket.fileno(), 3)
        self.assertFalse(socket._closed)

    def test_error_socket_closed_properly(self):
        """Closes socket if ContextManager exists with error."""
        with (
            Connection.bootstrap(self.associations_store) as connection,
            self.assertRaises(ResponseUnsuccesfulException),
        ):
            connection.get_logins('Nix!')

        self.assertIsClosed(connection.socket)

    def test_connection_context(self):
        """ContextManager of connection properly closes socket."""
        with Connection.bootstrap(self.associations_store) as connection:
            self.assertEqual(connection.get_databasehash(), self.database_hash)
            self.assertIsOpen(connection.socket)

        self.assertIsClosed(connection.socket)

        with connection as connection:
            self.assertEqual(connection.get_databasehash(), self.database_hash)
            self.assertIsOpen(connection.socket)

        self.assertIsClosed(connection.socket)

    def test_subsequent_reconnects(self):
        """Can be reconnected many times."""
        with Connection.bootstrap(self.associations_store) as connection:
            sockets = [
                connection.reconnect().socket,
                connection.reconnect().socket,
                connection.reconnect().socket,
                connection.reconnect().socket,
            ]

            connection.get_logins('https://example.com')

            # Opened and closed 4 distinct sockets, only the last one being open
            self.assertEqual(len(set(sockets)), 4)
            self.assertIsClosed(sockets[0])
            self.assertIsClosed(sockets[1])
            self.assertIsClosed(sockets[2])
            self.assertIsOpen(sockets[3])

        # Closed now too
        self.assertIsClosed(sockets[3])

    def test_get_all_logins(self):
        # Arrange
        expected = {
            'group': 'Root',
            'login': 'example_user',
            'name': 'Example Account',
            'password': '3x4mpl3 p4zzw0rd',
            'stringFields': [],
            'uuid': 'bbb816c3ebcb476a8de7c65ec1a9dfb8'
        }

        # System Under Test
        with Connection.bootstrap(self.associations_store) as connection:
            # Act
            logins = connection.get_all_logins('https://example.com')

        # Assert
        self.assertEqual(1, len(logins))
        self.assertEqual(expected, logins.pop())

    def test_get_logins_by_path(self):
        # Arrange
        expected = {
            'group': 'Subsubgroup',
            'login': 'sub_user',
            'name': 'Subentry',
            'password': 's3cur3',
            'stringFields': [],
            'uuid': '05736f4542254a6ea75ecdba07a35863'
        }
        # System Under Test
        with Connection.bootstrap(self.associations_store) as connection:
            # Act
            logins = connection.get_logins_by_path('Subgroup/Subsubgroup/Subentry')

        # Assert
        self.assertEqual(1, len(logins))
        self.assertEqual(expected, logins.pop())

    def test_get_logins_by_uuid(self):
        # Arrange
        expected = {
            'group': 'Subsubgroup',
            'login': 'sub_user',
            'name': 'Subentry',
            'password': 's3cur3',
            'stringFields': [],
            'uuid': '05736f4542254a6ea75ecdba07a35863'
        }
        # System Under Test
        with Connection.bootstrap(self.associations_store) as connection:
            # Act
            login = connection.get_login_by_uuid('05736f4542254a6ea75ecdba07a35863')

        # Assert
        self.assertEqual(expected, login)
