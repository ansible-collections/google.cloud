# Copyright (c) 2025 Red Hat
# GNU General Public License v3.0+ https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import absolute_import, annotations

import os
import os.path as ospath
import re
import pty
import shlex
import select
import shutil
import subprocess
import threading
import time
import yaml
import tempfile
import typing as T

import ansible.plugins.connection.ssh as sshconn
import ansible.errors as errors
import ansible.utils.display as display

_my_opts = {
    "gcloud_executable": {
        "description": [
            "Path to the gcloud executable, defaults to whatever is found in",
            "the PATH environment variable",
        ],
        "type": "string",
        "vars": [{"name": "ansible_gcloud_executable"}],
        "ini": [
            {"section": "gcloud", "key": "executable"},
        ],
    },
    "gcloud_configuration": {
        "description": ["Path to the gcloud configuration file if non default"],
        "type": "string",
        "vars": [{"name": "ansible_gcloud_configuration"}],
        "ini": [{"section": "gcloud", "key": "configuration"}],
        "env": [{"name": "CLOUDSDK_ACTIVE_CONFIG_NAME"}],
    },
    "gcloud_project": {
        "description": [
            "The Google Cloud project ID to use for this invocation.",
            "If omitted, then the current project is assumed",
        ],
        "type": "string",
        "vars": [{"name": "ansible_gcloud_project"}],
        "ini": [{"section": "gcloud", "key": "project"}],
        "env": [{"name": "CLOUDSDK_CORE_PROJECT"}],
    },
    "gcloud_account": {
        "description": ["Google cloud account to use for invocation"],
        "type": "string",
        "vars": [{"name": "ansible_gcloud_account"}],
        "ini": [{"section": "gcloud", "key": "account"}],
        "env": [{"name": "CLOUDSDK_CORE_ACCOUNT"}],
    },
    "gcloud_zone": {
        "description": ["The Google Cloud zone to use for the instance(s)"],
        "type": "string",
        "vars": [{"name": "ansible_gcloud_zone"}],
        "ini": [{"section": "gcloud", "key": "zone"}],
        "env": [{"name": "CLOUDSDK_COMPUTE_ZONE"}],
    },
    "gcloud_access_token_file": {
        "description": [
            "A file to read the access token from. ",
            "The credentials of the active account (if exists) will be ignored.",
        ],
        "type": "string",
        "vars": [{"name": "ansible_access_token_file"}],
        "ini": [{"section": "gcloud", "key": "access_token_file"}],
        "env": [{"name": "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE"}],
    },
}

# piggy back on top of upstream SSH plugin's docs, this somehow breaks ansible-doc but
# it still works for other ansible commands. This is expensive but I don't want to
# duplicate the entire doc string from ssh.py
_doc = yaml.safe_load(sshconn.DOCUMENTATION)
_doc["name"] = "gcloud-iap"
_doc["short_description"] = "connect using Google Cloud's Identity Aware Proxy (IAP)"
_doc["description"] = [
    "This connection plugin behaves almost like the stock SSH plugin, ",
    "but it creates a new IAP process per host in the inventory so connections ",
    "are tunneled through it. ",
    "This plugin requires you to have set authentication prior to using it.",
]
_doc["author"] = "Jorge A Gallegos (@kad)"
# Add custom opts for this plugin
_doc["options"].update(_my_opts)
# Change default to stock SSH key used by gcloud
_doc["options"]["private_key_file"]["default"] = "~/.ssh/google_compute_engine"

DOCUMENTATION = yaml.dump(_doc)

D = display.Display()
DEFAULT_GCLOUD: T.Optional[str] = shutil.which("gcloud")
DEFAULT_SSH_PORT: int = 22
PORT_REGEX = re.compile(r"\d+")


class IAP:
    host: str
    local_port: int
    remote_port: int
    master_fd: int
    up: bool = False
    process: T.Optional[subprocess.Popen] = None
    thread: T.Optional[threading.Thread] = None
    ready: threading.Event = threading.Event()
    output: T.List[str] = []

    def __init__(
        self,
        gcloud_bin: str,
        host: str,
        remote_port: int,
        project: T.Optional[str],
        account: T.Optional[str],
        zone: T.Optional[str],
        config: T.Optional[str] = None,
        token_file: T.Optional[str] = None,
    ) -> None:

        self.host = host
        self.remote_port = remote_port
        cmd: T.List[str] = [
            gcloud_bin,
            "compute",
            "start-iap-tunnel",
            host,
            str(self.remote_port),
        ]
        if config is not None:
            cmd.extend(
                [
                    "--configuration",
                    shlex.quote(ospath.realpath(ospath.expanduser(config.strip()))),
                ]
            )

        if project is not None:
            cmd.extend(
                [
                    "--project",
                    shlex.quote(project.strip()),
                ]
            )

        if account is not None:
            cmd.extend(
                [
                    "--account",
                    shlex.quote(account.strip()),
                ]
            )

        if zone is not None:
            cmd.extend(
                [
                    "--zone",
                    shlex.quote(zone.strip()),
                ]
            )

        if token_file is not None:
            cmd.extend(
                [
                    "--access-token-file",
                    shlex.quote(token_file.strip()),
                ]
            )

        D.vvv(f"IAP: CMD {' '.join(cmd)}", host=self.host)

        try:
            # start-iap-tunnel prints 2 lines:
            # - Picking local unused port [$PORT].
            # - Testing if tunnel connection works.
            # and only when the terminal is a pty, a 3rd line:
            # - Listening on port [$PORT].
            # The last line only displayed after the tunnel has been tested,
            # that's why we use a PTY for the subprocess
            self.master_fd, slave_fd = pty.openpty()
            self.process = subprocess.Popen(
                cmd, stdout=slave_fd, stderr=slave_fd, text=True, close_fds=True
            )
            os.close(slave_fd)
            self.thread = threading.Thread(target=self._monitor, daemon=True)
            self.thread.start()
            D.vvvvv("started IAP thread", host=self.host)
        except Exception as e:
            self.process = None
            raise Exception from e

    def _monitor(self) -> None:
        """Monitor the thread handling the IAP subprocess until it is 'up'"""

        while self.process is not None and self.process.poll() is None:
            rlist, _, _ = select.select([self.master_fd], [], [], 0.1)
            if rlist is not None:
                try:
                    output = os.read(self.master_fd, 1024).decode("utf-8")
                    if output:
                        for line in output.splitlines():
                            self.output.append(line)
                            if line.startswith("Listening on port"):
                                m = PORT_REGEX.search(line)
                                if m is not None:
                                    self.local_port = int(m.group())
                                    self.up = True
                                    D.vvv(
                                        f"IAP: LOCAL PORT {self.local_port}",
                                        host=self.host,
                                    )
                except OSError:  # pty is closed
                    break

            if self.up:  # no need to monitor if already up
                break

        if not self.ready.is_set():
            self.ready.set()

        os.close(self.master_fd)

    def terminate(self) -> None:
        """Gracefully terminate the IAP subprocess"""

        D.vvv("IAP: STOPPING TUNNEL", host=self.host)
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)  # wait up to 5 seconds to terminate IAP
            except subprocess.TimeoutExpired:
                self.process.kill()

            D.vvvvv("terminated/killed IAP", host=self.host)

        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=1)  # joining thread back should be quick


class Connection(sshconn.Connection):
    """
    This is pretty much the same as the upstream ssh plugin, just overloads
    the connection handling to start/stop the IAP tunnel with gcloud as appropriate
    """

    iaps: dict[str, IAP] = {}
    lock: threading.Lock = threading.Lock()

    gcloud_executable: T.Optional[str] = None
    ssh_config: str

    transport = "gcloud-iap"  # type: ignore[override]

    def __init__(self, *args: T.Any, **kwargs: T.Any) -> None:

        super(Connection, self).__init__(*args, **kwargs)

        # If the gcloud binary isn't found/configured, bail out immediately
        exec: T.Optional[str] = self.get_option("gcloud_executable")
        if exec is None:
            self.gcloud_executable = DEFAULT_GCLOUD
        else:
            self.gcloud_executable = exec

        if self.gcloud_executable is None:
            raise errors.AnsiblePluginError(
                "Plugin Error: no gcloud binary found in $PATH and "
                "no executable defined in ansible config"
            )

        # have to trick SSH to connect to localhost instead of the instances
        fd, self.ssh_config = tempfile.mkstemp(
            suffix="ssh_config", prefix="ansible_gcloud", text=True
        )
        with open(fd, "w") as fp:
            fp.write("Host *\n")
            fp.write("  HostName localhost\n")

    def _connect(self) -> Connection:
        """Upstream ssh is empty, overload with the stuff starting the IAP tunnel"""

        host: T.Optional[str] = self.get_option("host")
        project: T.Optional[str] = self.get_option("gcloud_project")
        account: T.Optional[str] = self.get_option("gcloud_account")
        zone: T.Optional[str] = self.get_option("gcloud_zone")
        token_file: T.Optional[str] = self.get_option("gcloud_access_token_file")
        config: T.Optional[str] = self.get_option("gcloud_configuration")
        port: T.Optional[int] = self.get_option("port")

        # this shouldn't happen, but still.
        if host is None:
            raise errors.AnsibleAssertionError("No host defined")

        with self.lock:
            if host not in self.iaps:
                self.iaps[host] = IAP(
                    str(self.gcloud_executable),
                    host=host,
                    remote_port=int(port or DEFAULT_SSH_PORT),
                    project=project,
                    zone=zone,
                    account=account,
                    config=config,
                    token_file=token_file,
                )

        success = self.iaps[host].ready.wait(timeout=5)
        is_up: bool = False
        for _ in range(3):
            is_up = self.iaps[host].up
            if success and is_up:
                D.vvv("IAP: TUNNEL IS UP", host=host)
                is_up = True
                break
            else:
                time.sleep(0.5)

        if not is_up:
            D.vvv("IAP: TUNNEL FAILURE", host=host)
            for line in self.iaps[host].output:
                D.vvvvv(line, host=host)
            raise errors.AnsibleRuntimeError("Failure when starting IAP tunnel")

        # override port with the random IAP port
        self.set_option("port", self.iaps[host].local_port)
        # disable host_key_checking because it's impossible to know ports beforehand
        self.set_option("host_key_checking", False)
        # prepend our generated tiny ssh config to all ssh_args if not already present
        if self.ssh_config not in str(self.get_option("ssh_args")):
            self.set_option(
                "ssh_args", f"-F {self.ssh_config} " + str(self.get_option("ssh_args"))
            )

        self._connected = True

        return self

    def close(self) -> None:
        """
        Upstream only marks the connection as closed, we have to terminate
        all IAP tunnels as well
        """

        # Terminate IAP
        with self.lock:
            for iap in self.iaps.values():
                iap.terminate()
            self.iaps.clear()

        # remove ssh config
        os.unlink(self.ssh_config)

        self._connected = False
