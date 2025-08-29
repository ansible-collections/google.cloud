# Copyright (c) 2025 Red Hat
# GNU General Public License v3.0+ https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import absolute_import, annotations

import os
import os.path as ospath
import pty
import shlex
import shutil
import subprocess
import typing as T

import ansible.errors as errors
import ansible.module_utils.common.text.converters as converters
import ansible.plugins.connection as connection
import ansible.utils.display as display

DOCUMENTATION = """
    author: Jorge A Gallegos <jgallego@redhat.com>
    short_description: Run tasks via Google Cloud's CLI
    description:
    - use the `gcloud` CLI command to connect and copy files
    - see https://cloud.google.com/sdk/gcloud/reference/compute/ssh and
      https://cloud.google.com/sdk/gcloud/reference/compute/scp for details
    - this connection plugin relies on `gcloud` to be available in your
      PATH and for authentication to be done prior to usage

    options:
        instance:
            required: true
            description:
            - The name of the instance to connect to.
            type: string
            vars:
            - name: inventory_hostname
            - name: ansible_host
            - name: ansible_ssh_host
            - name: ansible_gcloud_instance
        remote_user:
            required: true
            description:
            - The user to log in as.
            type: string
            vars:
            - name: ansible_user
            - name: ansible_ssh_user
            - name: ansible_gcloud_user
            env:
            - name: ANSIBLE_REMOTE_USER
            - name: ANSIBLE_GCLOUD_REMOTE_USER
            ini:
            - section: defaults
              key: remote_user
            - section: gcloud
              key: remote_user
            cli:
            - name: user
            keyword:
            - name: remote_user
        gcloud_executable:
            description:
            - Path to the gcloud executable, defaults to whatever is found in
              the PATH environment variable
            type: string
            vars:
            - name: ansible_gcloud_executable
            ini:
            - section: gcloud
              key: executable
            cli:
            - name: gcloud_executable
              option: --gcloud-executable
        configuration:
            description:
            - File name of the configuration to use for this command invocation
            type: string
            vars:
            - name: ansible_gcloud_configuration
            ini:
            - section: gcloud
              key: configuration
            env:
            - name: CLOUDSDK_ACTIVE_CONFIG_NAME
            cli:
            - name: configuration
              option: --gcloud-configuration
        project:
            required: true
            description:
            - The Google Cloud project ID to use for this invocation.
              If omitted, then the current project is assumed
            type: string
            vars:
            - name: ansible_gcloud_project
            ini:
            - section: gcloud
              key: project
            env:
            - name: CLOUDSDK_PROJECT_ID
            cli:
            - name: project
              option: --gcloud-project
        zone:
            required: true
            description:
            - Configures the zone to use when connecting
            type: string
            vars:
            - name: ansible_gcloud_zone
            ini:
            - section: gcloud
              key: zone
            env:
            - name: CLOUDSDK_COMPUTE_ZONE
            cli:
            - name: zone
              option: --gcloud-zone
        private_key_file:
            description:
            - The path to the SSH key file. By default,
              this is ~/.ssh/google_compute_engine
            type: string
            vars:
            - name: ansible_private_key_file
            - name: ansible_ssh_private_key_file
            - name: ansible_gcloud_private_key_file
            env:
            - name: ANSIBLE_PRIVATE_KEY_FILE
            - name: ANSIBLE_GCLOUD_PRIVATE_KEY_FILE
            ini:
            - section: defaults
              key: private_key_file
            - section: gcloud
              key: private_key_file
            cli:
            - name: private_key_file
              option: --gcloud-private-key
            default: ~/.ssh/google_compute_engine
        use_tty:
            description: add -tt to ssh commands to force tty allocation
            type: bool
            default: true
            ini:
            - section: ssh_connection
              key: usetty
            - section: gcloud
              key: usetty
            env:
            - name: ANSIBLE_SSH_USE_TTY
            vars:
            - name: ansible_ssh_use_tty
            - name: ansible_gcloud_use_tty
        timeout:
            description:
            - This is the default amount of time we will wait while establishing
              a connection.
            - This also controls how long we can wait to access reading the
              connection once established.
            default: 10
            type: int
            env:
            - name: ANSIBLE_TIMEOUT
            - name: ANSIBLE_SSH_TIMEOUT
            - name: ANSIBLE_GCLOUD_TIMEOUT
            ini:
            - section: defaults
              key: timeout
            - section: ssh_connection
              key: timeout
            - section: gcloud
              key: timeout
            vars:
            - name: ansible_ssh_timeout
            - name: ansible_gcloud_timeout
            cli:
            - name: timeout
        ssh_args:
            description: Arguments to pass to all SSH CLI tools.
            type: string
            default: '-C -o ControlMaster=auto -o ControlPersist=60s'
            ini:
            - section: ssh_connection
              key: ssh_args
            - section: gcloud
              key: ssh_args
            env:
            - name: ANSIBLE_SSH_ARGS
            vars:
            - name: ansible_ssh_args
        ssh_extra_args:
            description:
            - Extra arguments exclusive to SSH
            type: string
            vars:
            - name: ansible_ssh_extra_args
            env:
            - name: ANSIBLE_SSH_EXTRA_ARGS
            ini:
            - section: ssh_connection
              key: ssh_extra_args
            - section: gcloud
              key: ssh_extra_args
            cli:
            - name: ssh_extra_args
        scp_extra_args:
            description: Extra exclusive to SCP
            type: string
            vars:
            - name: ansible_scp_extra_args
            env:
            - name: ANSIBLE_SCP_EXTRA_ARGS
            ini:
            - section: ssh_connection
              key: scp_extra_args
            - section: gcloud
              key: scp_extra_args
            cli:
            - name: scp_extra_args
"""

D = display.Display()
DEFAULT_TIMEOUT: int = 10
DEFAULT_GCLOUD: str | None = shutil.which("gcloud")


class Connection(connection.ConnectionBase):
    """Connections via `gcloud compute ssh`"""

    gcloud_executable: str | None = None

    has_pipelining = False
    transport = "gcloud-ssh"  # type: ignore[override]

    def __init__(self, *args: T.Any, **kwargs: T.Any) -> None:

        super(Connection, self).__init__(*args, **kwargs)

        exec: str | None = self.get_option("gcloud_executable")
        if exec is None:
            self.gcloud_executable = DEFAULT_GCLOUD
        else:
            self.gcloud_executable = exec

        if self.gcloud_executable is None:
            raise errors.AnsiblePluginError(
                "Plugin Error: no gcloud binary found in $PATH and "
                "no executable defined in ansible config"
            )

    def _connect(self) -> Connection:
        """connect to the instance using gcloud compute ssh"""

        return self

    def close(self) -> None:
        """mark connection as closed"""

        self._connected = False

    def _build_flags_for(self, what: str) -> T.List[str]:
        flags: T.List[str] = []
        args: str = self.ssh_args or ""

        args += f" -o ConnectTimeout={self.timeout} "

        if what == "ssh":
            args += self.ssh_extra_args or ""
        elif what == "scp":
            args += self.scp_extra_args or ""

        pieces: T.List[str] = shlex.split(args.strip())
        flag: str = ""
        for piece in pieces:
            if flag == "" and piece.startswith("-"):
                # start of a flag
                flag = piece
                continue
            elif flag != "" and piece.startswith("-"):
                # we encountered a flag after another flag
                # append the previous flag first and continue
                flags.append(f"--{what}-flag={flag}")
                flag = piece
                continue
            elif not piece.startswith("-"):
                # this is the argument to the ongoing flag
                # concatenate and append
                flag += " " + piece
                flags.append(f"--{what}-flag={flag}")
                flag = ""
            else:
                pass

        # if there are any remnant flags, add them
        if flag != "":
            flags.append(f"--{what}-flag={flag}")

        D.vvvvv(f"flags: {flags}", host=self.host)

        return flags

    def _build_command(
        self,
        what: str,
        cmd: str,
        in_path: str | None = None,  # only used for scp
        out_path: str | None = None,  # only used for scp
    ) -> T.List[str]:
        parts: T.List[str]

        parts = [
            self.gcloud_executable or "",  # to silence pyright
            "compute",
            what,
            f"--project={self.gcp_project}",
            f"--zone={self.gcp_zone}",
            f"--ssh-key-file={self.private_key_file}",
            "--quiet",  # no prompts
            "--no-user-output-enabled",  # no extra gcloud output
            "--tunnel-through-iap",
        ]
        if self.gcp_configuration is not None:
            parts.append(f"--configuration={self.gcp_configuration}")

        parts.extend(self._build_flags_for(what))

        # handle options for ssh only
        if what == "ssh":
            if self.use_tty:
                parts.append("--ssh-flag=-tt")
            parts.extend([f"{self.user}@{self.host}", "--", cmd])

        elif what == "scp":
            parts.append("--compress")
            if cmd == "put":
                parts.append(str(in_path))
                parts.append(f"{self.user}@{self.host}:{out_path}")
            elif cmd == "fetch":
                parts.append(f"{self.user}@{self.host}:{in_path}")
                parts.append(str(out_path))

        return parts

    def _run(
        self,
        cmd: list[str],
        in_data: bytes | None,
        sudoable: bool = True,
        checkrc: bool = True,
    ) -> tuple[int, bytes, bytes]:

        D.vvv(f"EXEC: {shlex.join(cmd)}", host=self.host)

        D.vvvvv("running command with Popen()", host=self.host)
        # I could just not open a pty and be done with it, because I am
        # not writing the whole pipelining and keyboard interaction just now.
        # It may come at a later date so I am just laying the groundwork
        p: subprocess.Popen[bytes] | None = None
        master_fd: int = 0
        slave_fd: int = 0
        if in_data is None:  # attempt to open a pty
            try:
                master_fd, slave_fd = pty.openpty()
                p = subprocess.Popen(
                    cmd,
                    stdin=slave_fd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                # we don't need the input half to be open
                os.close(slave_fd)
                D.vvvvv("created pty subprocess", host=self.host)
            except OSError:
                D.vvvvv("failed to create pty", host=self.host)

        if p is None:  # fallback to non-pty
            try:
                p = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                D.vvvvv("created non-pty subprocess", host=self.host)
            except OSError as ose:
                raise errors.AnsibleError(
                    "Unable to execute ssh command on controller."
                ) from ose
        D.vvvvv("done running command with Popen()", host=self.host)

        D.vvvvv("getting output with communicate()", host=self.host)
        if p is not None:
            # output: t.Tuple[t.Optional[bytes], t.Optional[bytes]] = p.communicate()
            stdout, stderr = p.communicate()
        D.vvvvv("done getting output with communicate()", host=self.host)

        # close the last half of the pty if created
        if master_fd != 0:
            os.close(master_fd)

        D.debug(f"stdout: >>>>>{stdout}<<<<<", host=self.host)
        D.debug(f"stderr: >>>>>{stderr}<<<<<", host=self.host)
        return (p.returncode, stdout, stderr)

    def exec_command(
        self, cmd: str, in_data: bytes | None = None, sudoable: bool = True
    ) -> tuple[int, bytes, bytes]:
        """run a command on the remote instance"""

        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        self.host: str | None = self.get_option("instance")
        self.user: str | None = self.get_option("remote_user")
        self.ssh_args: str | None = self.get_option("ssh_args")
        self.ssh_extra_args: str | None = self.get_option("ssh_extra_args")
        self.scp_extra_args: str | None = self.get_option("scp_extra_args")
        self.private_key_file: str | None = self.get_option("private_key_file")
        self.use_tty: bool | None = self.get_option("use_tty")
        if self.private_key_file is not None:  # to silence pyright
            self.private_key_file = ospath.abspath(
                ospath.expanduser(self.private_key_file)
            )
        self.gcp_configuration: str | None = self.get_option("configuration")
        self.gcp_project: str | None = self.get_option("project")
        self.gcp_zone: str | None = self.get_option("zone")
        self.timeout: int = int(self.get_option("timeout") or DEFAULT_TIMEOUT)

        display.Display().vvv(
            f"GCLOUD SSH CONNECTION FOR USER: {self.user}", host=self.host
        )

        full_cmd: T.List[str] = self._build_command("ssh", cmd)

        return self._run(cmd=full_cmd, in_data=in_data, sudoable=sudoable)

    def put_file(self, in_path: str, out_path: str) -> tuple[int, bytes, bytes]:  # type: ignore[override]
        """uploads a file to the cloud instance"""

        super(Connection, self).put_file(in_path, out_path)

        self.host: str | None = self.get_option("instance")
        self.user: str | None = self.get_option("remote_user")
        self.ssh_args: str | None = self.get_option("ssh_args")
        self.scp_extra_args: str | None = self.get_option("scp_extra_args")
        self.private_key_file: str | None = self.get_option("private_key_file")
        if self.private_key_file is not None:  # to silence pyright
            self.private_key_file = ospath.abspath(
                ospath.expanduser(self.private_key_file)
            )
        self.gcp_configuration: str | None = self.get_option("configuration")
        self.gcp_project: str | None = self.get_option("project")
        self.gcp_zone: str | None = self.get_option("zone")
        self.timeout: int = int(self.get_option("timeout") or DEFAULT_TIMEOUT)

        D.vvv(f"PUT: {in_path} TO {out_path}", host=self.host)
        if not ospath.exists(
            converters.to_bytes(in_path, errors="surrogate_or_strict")
        ):
            raise errors.AnsibleFileNotFound(
                f"File or module does not exist: {converters.to_native(in_path)}"
            )

        full_cmd: T.List[str] = self._build_command("scp", "put", in_path, out_path)

        return self._run(full_cmd, None)

    def fetch_file(self, in_path: str, out_path: str) -> None:
        """downloads a file from the cloud instance"""

        super(Connection, self).fetch_file(in_path, out_path)
