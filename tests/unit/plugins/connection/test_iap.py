# Copyright (c) 2026, Google Inc.
# GNU General Public License v3.0+ https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

import os
import subprocess
import threading
import unittest
from io import StringIO
from unittest import mock

from ansible.errors import (
    AnsibleAssertionError,
    AnsiblePluginError,
    AnsibleRuntimeError,
)
from ansible.playbook.play_context import PlayContext
from ansible.plugins.loader import connection_loader
from ansible_collections.google.cloud.plugins.connection import iap


def _make_connection(gcloud_executable="/usr/bin/gcloud"):
    """Build a Connection instance with gcloud_executable resolution mocked."""

    play_context = PlayContext()
    with mock.patch.object(
        iap.Connection, "get_option", return_value=gcloud_executable
    ):
        conn = connection_loader.get("google.cloud.iap", play_context, StringIO())
    # the tunnel registry is a class attribute shared by all instances, make it
    # instance-local so tests don't leak state into each other
    conn.iaps = {}
    return conn


class TestIAPConnectionInit(unittest.TestCase):
    def test_uses_configured_gcloud_executable(self):
        conn = _make_connection(gcloud_executable="/opt/gcloud/bin/gcloud")
        self.assertEqual(conn.gcloud_executable, "/opt/gcloud/bin/gcloud")

    def test_falls_back_to_default_gcloud(self):
        with mock.patch.object(iap, "DEFAULT_GCLOUD", "/usr/bin/gcloud"):
            conn = _make_connection(gcloud_executable=None)
            self.assertEqual(conn.gcloud_executable, "/usr/bin/gcloud")

    def test_raises_when_no_gcloud_found(self):
        with (
            mock.patch.object(iap, "DEFAULT_GCLOUD", None),
            self.assertRaises(AnsiblePluginError),
        ):
            _make_connection(gcloud_executable=None)


class TestIAPConnectionConnect(unittest.TestCase):
    def setUp(self):
        self.conn = _make_connection()
        self.options = {
            "host": "my-instance",
            "gcloud_project": None,
            "gcloud_account": None,
            "gcloud_zone": None,
            "gcloud_access_token_file": None,
            "gcloud_configuration": None,
            "port": None,
            "timeout": 10,
            "known_hosts_file": "~/.ssh/google_compute_known_hosts",
            "ssh_args": "-C -o ControlMaster=auto",
        }
        self.conn.get_option = mock.MagicMock(
            side_effect=lambda name, hostvars=None: self.options[name]
        )
        self.conn.set_option = mock.MagicMock()

    def _fake_tunnel(self, up=True, ready=True, local_port=23456):
        tunnel = mock.MagicMock()
        tunnel.ready.wait.return_value = ready
        tunnel.up = up
        tunnel.local_port = local_port
        tunnel.output = []
        return tunnel

    def test_connect_starts_tunnel_and_updates_ssh_options(self):
        with mock.patch.object(iap, "IAP") as mock_iap_cls:
            mock_iap_cls.return_value = self._fake_tunnel(local_port=23456)

            result = self.conn._connect()

        self.assertIs(result, self.conn)
        self.assertTrue(self.conn._connected)
        mock_iap_cls.assert_called_once_with(
            self.conn.gcloud_executable,
            host="my-instance",
            remote_port=22,
            project=None,
            zone=None,
            account=None,
            config=None,
            token_file=None,
        )
        self.conn.set_option.assert_any_call("port", 23456)
        ssh_args_call = [
            call
            for call in self.conn.set_option.call_args_list
            if call.args[0] == "ssh_args"
        ]
        self.assertEqual(len(ssh_args_call), 1)
        new_ssh_args = ssh_args_call[0].args[1]
        self.assertIn("-oHostname=localhost", new_ssh_args)
        self.assertIn("-oHostKeyAlias=my-instance", new_ssh_args)

    def test_connect_reuses_existing_tunnel(self):
        with mock.patch.object(iap, "IAP") as mock_iap_cls:
            mock_iap_cls.return_value = self._fake_tunnel()

            self.conn._connect()
            self.conn._connect()

        mock_iap_cls.assert_called_once()

    def test_connect_raises_when_tunnel_never_comes_up(self):
        with (
            mock.patch.object(iap, "IAP") as mock_iap_cls,
            mock.patch.object(iap.time, "sleep"),
        ):
            mock_iap_cls.return_value = self._fake_tunnel(up=False, ready=False)

            with self.assertRaises(AnsibleRuntimeError):
                self.conn._connect()

    def test_connect_raises_without_host(self):
        self.options["host"] = None

        with self.assertRaises(AnsibleAssertionError):
            self.conn._connect()


class TestIAPConnectionExecCommand(unittest.TestCase):
    def test_exec_command_connects_before_delegating(self):
        conn = _make_connection()
        conn._connect = mock.MagicMock()

        with mock.patch.object(
            iap.sshconn.Connection, "exec_command", return_value=(0, b"out", b"err")
        ) as mock_super:
            result = conn.exec_command("ls", in_data=None, sudoable=True)

        conn._connect.assert_called_once()
        mock_super.assert_called_once_with("ls", in_data=None, sudoable=True)
        self.assertEqual(result, (0, b"out", b"err"))


class TestIAPConnectionClose(unittest.TestCase):
    def test_close_terminates_all_tunnels(self):
        conn = _make_connection()
        conn.get_option = mock.MagicMock(return_value="my-instance")
        tunnel_a = mock.MagicMock()
        tunnel_b = mock.MagicMock()
        conn.iaps = {"host-a": tunnel_a, "host-b": tunnel_b}
        conn._connected = True

        conn.close()

        tunnel_a.terminate.assert_called_once()
        tunnel_b.terminate.assert_called_once()
        self.assertEqual(conn.iaps, {})
        self.assertFalse(conn._connected)


class TestIAPTunnelCommand(unittest.TestCase):
    def _build_tunnel(self, **kwargs):
        master_fd, slave_fd = os.pipe()
        with (
            mock.patch.object(iap.pty, "openpty", return_value=(master_fd, slave_fd)),
            mock.patch.object(iap.subprocess, "Popen") as mock_popen,
            mock.patch.object(iap.threading, "Thread"),
        ):
            mock_popen.return_value = mock.MagicMock()
            tunnel = iap.IAP("/usr/bin/gcloud", "my-instance", 22, **kwargs)
        os.close(master_fd)
        return tunnel, mock_popen

    def test_minimal_command(self):
        tunnel, mock_popen = self._build_tunnel(project=None, account=None, zone=None)  # noqa: RUF059
        cmd = mock_popen.call_args.args[0]
        self.assertEqual(
            cmd,
            ["/usr/bin/gcloud", "compute", "start-iap-tunnel", "my-instance", "22"],
        )

    def test_configuration_is_passed_as_literal_identifier(self):
        """Regression test for #759

        ``gcloud_configuration``/``--configuration`` is a named gcloud CLI
        configuration identifier, not a filesystem path.
        """
        tunnel, mock_popen = self._build_tunnel(  # noqa: RUF059
            project=None,
            account=None,
            zone=None,
            config="my-named-config",
        )
        cmd = mock_popen.call_args.args[0]

        self.assertIn("--configuration", cmd)
        self.assertEqual(cmd[cmd.index("--configuration") + 1], "my-named-config")

    def test_full_command(self):
        tunnel, mock_popen = self._build_tunnel(  # noqa: RUF059
            project="my-project",
            account="me@example.com",
            zone="us-central1-a",
            config="my-config",
            token_file="/tmp/token",
        )
        cmd = mock_popen.call_args.args[0]
        self.assertEqual(
            cmd,
            [
                "/usr/bin/gcloud",
                "compute",
                "start-iap-tunnel",
                "my-instance",
                "22",
                "--configuration",
                "my-config",
                "--project",
                "my-project",
                "--account",
                "me@example.com",
                "--zone",
                "us-central1-a",
                "--access-token-file",
                "/tmp/token",
            ],
        )


class TestIAPTunnelMonitor(unittest.TestCase):
    def _make_tunnel(self, poll_return=None):
        tunnel = iap.IAP.__new__(iap.IAP)
        tunnel.host = "my-instance"
        tunnel.process = mock.MagicMock()
        tunnel.process.poll.return_value = poll_return
        tunnel.output = []
        tunnel.ready = threading.Event()
        tunnel.up = False
        return tunnel

    def test_monitor_detects_listening_port(self):
        tunnel = self._make_tunnel()
        read_fd, write_fd = os.pipe()
        tunnel.master_fd = read_fd
        os.write(
            write_fd,
            b"Picking local unused port [12345].\nListening on port [12345].\n",
        )
        os.close(write_fd)

        tunnel._monitor()

        self.assertTrue(tunnel.up)
        self.assertEqual(tunnel.local_port, 12345)
        self.assertTrue(tunnel.ready.is_set())

    def test_monitor_sets_ready_when_process_exits(self):
        tunnel = self._make_tunnel(poll_return=1)
        read_fd, write_fd = os.pipe()
        tunnel.master_fd = read_fd
        os.close(write_fd)

        tunnel._monitor()

        self.assertFalse(tunnel.up)
        self.assertTrue(tunnel.ready.is_set())


class TestIAPTunnelTerminate(unittest.TestCase):
    def _make_tunnel(self):
        tunnel = iap.IAP.__new__(iap.IAP)
        tunnel.host = "my-instance"
        tunnel.process = mock.MagicMock()
        tunnel.process.poll.return_value = None
        tunnel.thread = mock.MagicMock()
        tunnel.thread.is_alive.return_value = True
        return tunnel

    def test_terminate_graceful(self):
        tunnel = self._make_tunnel()

        tunnel.terminate()

        tunnel.process.terminate.assert_called_once()
        tunnel.process.wait.assert_called_once_with(timeout=5)
        tunnel.process.kill.assert_not_called()
        tunnel.thread.join.assert_called_once_with(timeout=1)

    def test_terminate_kills_on_timeout(self):
        tunnel = self._make_tunnel()
        tunnel.process.wait.side_effect = subprocess.TimeoutExpired(
            cmd="gcloud", timeout=5
        )

        tunnel.terminate()

        tunnel.process.terminate.assert_called_once()
        tunnel.process.kill.assert_called_once()


if __name__ == "__main__":
    unittest.main()
