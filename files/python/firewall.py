"""SRX configuration helper class."""
# pylint: disable=inconsistent-return-statements

# Standard library
from typing import List, Optional

# Third Party
from jnpr.junos import Device  # type: ignore
from jnpr.junos.utils.config import Config  # type: ignore
from jnpr.junos.exception import ConnectError, ConnectUnknownHostError, ConnectTimeoutError, ConnectRefusedError, ConnectAuthError

# Local
from pydantic import BaseModel


class Host(BaseModel):
    """Data model for a device."""

    name: str
    ip: str


class Credentials(BaseModel):
    """Data model for authentication."""

    username: str
    password: Optional[str] = None
    sshkey: Optional[str] = None


class InboundTraffic(BaseModel):
    """Allowed types of services and protocols."""

    system_services: List[str]
    protocols: List[str]


class SecurityZones(BaseModel):
    """Data model for Security Zone configuration."""

    app_tracking: Optional[bool] = False
    inbound_traffic: Optional[InboundTraffic]
    interfaces: List[str]
    name: str


class Configuration(BaseModel):
    """Device configuration."""

    zones: List[SecurityZones]


class SrxHelper(BaseModel):
    """Helper for interacting with the Northstar API."""

    credentials: Credentials
    inventory: List[Host]
    configuration: Configuration

    def get_status(self):
        """Testing API reachability with a version pull."""

        try:
            """Build connection, print to screen hello world message."""
            for each in self.inventory:
                dev = Device(
                    host=each.ip,
                    user=self.credentials.username,
                    passwd=self.credentials.password,
                    ssh_private_key_file=self.credentials.sshkey,
                    gather_facts=False,
                )
                dev.open()

                print(f"successfully tested connection to {each.name}")  # noqa T001

                dev.close()

        except (ConnectError, ConnectUnknownHostError, ConnectTimeoutError, ConnectRefusedError, ConnectAuthError) as response_error:
            """Gracefully exit upon reaching an error."""
            print(f"unsuccessful connection to {each.name}: {response_error}")  # noqa T001
            raise SystemExit from response_error

    def security_zones(self):
        """Configure security zones."""

        try:
            """Build connection, print to screen hello world message."""
            for each in self.inventory:
                dev = Device(
                    host=each.ip,
                    user=self.credentials.username,
                    passwd=self.credentials.password,
                    ssh_private_key_file=self.credentials.sshkey,
                    gather_facts=False,
                )
                dev.open()

                print(f"successfully tested connection to {each.name}")  # noqa T001

                configuration = Config(dev)

                configuration.load(
                    template_path="templates/security_zones.j2",
                    template_vars=self.configuration,
                    format="set"
                )

                if configuration.pdiff():
                    configuration.pdiff()

                if configuration.commit_check():
                    configuration.commit()
                else:
                    configuration.rollback()

                dev.close()

        except (ConnectError, ConnectUnknownHostError, ConnectTimeoutError, ConnectRefusedError, ConnectAuthError) as response_error:
            """Gracefully exit upon reaching an error."""
            print(f"unsuccessful connection to {each.name}: {response_error}")  # noqa T001
            raise SystemExit from response_error
