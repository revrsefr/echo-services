"""irctest controller for fedserv.

Copy (or symlink) this file into irctest's ``irctest/controllers/`` directory,
then run the services tests against an isolated InspIRCd + fedserv:

    FEDSERV_BIN=/path/to/federated-services/target/release/fedserv \\
    PATH=/path/to/inspircd/run/bin:$PATH \\
    python -m pytest \\
        --controller=irctest.controllers.inspircd \\
        --services-controller=irctest.controllers.fedserv_services \\
        irctest/server_tests/account_registration.py

irctest spawns its own ircd + services on random ports, so this never touches a
real network. See https://github.com/progval/irctest
"""
import os
import shutil
from typing import Optional, Type

import irctest.cases
import irctest.runner
from irctest.basecontrollers import BaseServicesController, DirectoryBasedController

CONFIG = """\
[uplink]
host = "{server_hostname}"
port = {server_port}
password = "password"

[server]
name = "My.Little.Services"
sid = "42S"
description = "Federated Services"
protocol = 1206
"""


class FedservController(BaseServicesController, DirectoryBasedController):
    software_name = "fedserv"
    saslserv = "NickServ"

    def run(self, protocol: str, server_hostname: str, server_port: int) -> None:
        self.create_config()
        assert protocol in ("inspircd", "inspircd3"), f"fedserv speaks inspircd, not {protocol}"

        binary = (
            os.environ.get("FEDSERV_BIN")
            or shutil.which("fedserv")
            or "target/release/fedserv"
        )

        with self.open_file("config.toml") as fd:
            fd.write(CONFIG.format(server_hostname=server_hostname, server_port=server_port))

        self.proc = self.execute([binary, "config.toml"], cwd=self.directory)

    def registerUser(
        self,
        case: irctest.cases.BaseServerTestCase,
        username: str,
        password: Optional[str] = None,
    ) -> None:
        # NickServ REGISTER is a single PRIVMSG, so a password that would push
        # the line past the 512-byte IRC limit can't be registered intact. Like
        # the reference services controllers, skip rather than silently truncate.
        assert password
        if len(password.encode()) > 400:
            raise irctest.runner.NotImplementedByController(
                "Passwords too long to REGISTER in a single IRC message"
            )
        super().registerUser(case, username, password)


def get_irctest_controller_class() -> Type[FedservController]:
    return FedservController
