"""
Configure a Juniper SRX firewall with PyEZ.
"""

# 3rd Party imports
import ipdb
import yaml

# Local imports
from firewall import SrxHelper


def main():
    """Main execution block."""

    # create project object, passing in YAML file objects
    srx_configuration = SrxHelper(
        inventory=config_file["inventory"],
        credentials=config_file["credentials"],
        configuration=config_file["configuration"],
    )

    srx_configuration.security_zones()
    srx_configuration.security_policies()
    srx_configuration.security_nat()


if __name__ == "__main__":

    # load contents of our config.yaml file into an object named `epe`
    with open("config.yaml", "r", encoding="utf-8") as file:
        config_file = yaml.safe_load(file)

    main()
