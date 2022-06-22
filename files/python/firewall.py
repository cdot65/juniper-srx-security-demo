"""SRX configuration helper class."""
# pylint: disable=inconsistent-return-statements

# Standard library
from typing import List, Optional
import logging

# Third Party
from jnpr.junos import Device  # type: ignore
from jnpr.junos.utils.config import Config  # type: ignore
from jnpr.junos.exception import (
    ConnectError,
    ConnectUnknownHostError,
    ConnectTimeoutError,
    ConnectRefusedError,
    ConnectAuthError,
)

# Local
from pydantic import BaseModel


# Define logging level of our script
logger = logging.getLogger()
logger.setLevel(logging.ERROR)
console_handler = logging.StreamHandler()
log_format = "%(asctime)s | %(levelname)s: %(message)s"
console_handler.setFormatter(logging.Formatter(log_format))
logger.addHandler(console_handler)


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


class NatRules(BaseModel):
    """Rules for each NAT statement."""

    name: str
    address_src: List[str]
    address_dst: List[str]
    application: List[str]
    action: List[str]


class NatRuleSet(BaseModel):
    """Rule set for NAT policies."""

    name: str
    zone_src: List[str]
    zone_dst: List[str]
    rules: List[NatRules]


class NatSource(BaseModel):
    """Configuration for source NAT."""

    ruleset: List[NatRuleSet]


class Nat(BaseModel):
    """Configuration for source NAT."""

    source: Optional[NatSource] = None


class SecurityZones(BaseModel):
    """Data model for Security Zone configuration."""

    app_tracking: Optional[bool] = False
    inbound_traffic: Optional[InboundTraffic]
    interfaces: List[str]
    name: str


class SecurityPolicies(BaseModel):
    """Data model for Security Policy configuration."""

    action: List[str]
    address_src: List[str]
    address_dst: List[str]
    application: List[str]
    log: Optional[bool] = False
    name: str
    zone_dst: List[str]
    zone_src: List[str]


class SecurityNat(BaseModel):
    """Data model for Security NAT configuration."""

    source: Optional[NatSource]


class Configuration(BaseModel):
    """Device configuration."""

    zones: List[SecurityZones]
    policies: List[SecurityPolicies]
    nat: SecurityNat


class SrxHelper(BaseModel):
    """Helper for interacting with the Northstar API."""

    credentials: Credentials
    inventory: List[Host]
    configuration: Configuration

    def _connection_builder(self, each):
        """Return a connection object."""

        device_connection = Device(
            host=each.ip,
            user=self.credentials.username,
            passwd=self.credentials.password,
            ssh_private_key_file=self.credentials.sshkey,
            gather_facts=False,
        )

        return device_connection

    def _print_error(self, error):
        """Return a message to the console regarding the error."""

        return logger.error(error)

    def get_status(self):
        """Testing API reachability with a version pull."""

        try:
            """Build connection, print to screen hello world message."""
            for each in self.inventory:
                dev = self._connection_builder(each)
                dev.open()
                print(f"successfully tested connection to {each.name}")  # noqa T001
                dev.close()

        except (
            ConnectError,
            ConnectUnknownHostError,
            ConnectTimeoutError,
            ConnectRefusedError,
            ConnectAuthError,
        ) as response_error:
            """Gracefully exit upon reaching an error."""

            self._print_error(response_error)

            raise SystemExit from response_error

    def security_zones(self):
        """Configure security zones."""

        try:
            """Build connection, print to screen hello world message."""
            for each in self.inventory:
                dev = self._connection_builder(each)
                dev.open()

                print(f"{each.name}: Pushing Security Zones")  # noqa T001

                pyez_connection = Config(dev)

                pyez_connection.load(
                    template_path="templates/security_zones.j2",
                    template_vars=self.configuration,
                    format="set",
                )

                if pyez_connection.pdiff():
                    pyez_connection.pdiff()

                if pyez_connection.commit_check():
                    pyez_connection.commit()
                else:
                    pyez_connection.rollback()

                dev.close()

        except (
            ConnectError,
            ConnectUnknownHostError,
            ConnectTimeoutError,
            ConnectRefusedError,
            ConnectAuthError,
        ) as response_error:
            """Gracefully exit upon reaching an error."""

            self._print_error(response_error)

            raise SystemExit from response_error

    def security_policies(self):
        """Configure security policies."""

        try:
            """Build connection, print to screen hello world message."""
            for each in self.inventory:
                dev = self._connection_builder(each)
                dev.open()

                print(f"{each.name}: Pushing Security Policy")  # noqa T001

                pyez_connection = Config(dev)

                pyez_connection.load(
                    template_path="templates/security_policies.j2",
                    template_vars=self.configuration,
                    format="set",
                )

                if pyez_connection.pdiff():
                    pyez_connection.pdiff()

                if pyez_connection.commit_check():
                    pyez_connection.commit()
                else:
                    pyez_connection.rollback()

                dev.close()

        except (
            ConnectError,
            ConnectUnknownHostError,
            ConnectTimeoutError,
            ConnectRefusedError,
            ConnectAuthError,
        ) as response_error:
            """Gracefully exit upon reaching an error."""

            self._print_error(response_error)

            raise SystemExit from response_error

    def security_nat(self):
        """Configure security nat."""

        try:
            """Build connection, print to screen hello world message."""
            for each in self.inventory:
                dev = self._connection_builder(each)
                dev.open()

                print(f"{each.name}: Pushing NAT config")  # noqa T001

                pyez_connection = Config(dev)

                pyez_connection.load(
                    template_path="templates/security_nat.j2",
                    template_vars=self.configuration,
                    format="set",
                )

                if pyez_connection.pdiff():
                    pyez_connection.pdiff()

                if pyez_connection.commit_check():
                    pyez_connection.commit()
                else:
                    pyez_connection.rollback()

                dev.close()

        except (
            ConnectError,
            ConnectUnknownHostError,
            ConnectTimeoutError,
            ConnectRefusedError,
            ConnectAuthError,
        ) as response_error:
            """Gracefully exit upon reaching an error."""

            self._print_error(response_error)

            raise SystemExit from response_error
