"""Generate production configurations and push to our network devices."""
import yaml  # type: ignore
from jnpr.junos import Device  # type: ignore
from jnpr.junos.utils.config import Config  # type: ignore


def inventory():
    """Load our inventory.yaml into a python object called routers."""
    devices = yaml.safe_load(open("inventory.yaml"))
    return devices


def main(devices):
    """Build connection, template config, and push to device.

    Loop over our list of routers that we imported from inventory.py
    Utilize the ID as the last octet within the IP address of the router
    Once the connection is open, print a message to the console
    Ingest the configuration variables stored in our device's' YAML file
    """
    for each in devices["routers"]:
        dev = Device(
            host=f"{each['ip']}",
            user="jcluser",
            password="Juniper!1",
            gather_facts=False,
        )
        dev.open()

        print(f"connected to {each['name']}")  # noqa T001

        """
        creating an empty dictionary called `data`
        then stuffing our YAML vars into it as 'configuration'
        this is to help handle PyEZ loading YAML vars differently than Jinja2
        """
        data = dict()
        data["configuration"] = yaml.safe_load(open(f"vars/{each['name']}.yaml"))

        configuration = Config(dev)

        configuration.load(
            template_path="templates/junos.j2", template_vars=data, format="set"
        )
        configuration.pdiff()
        if configuration.commit_check():
            configuration.commit()
        else:
            configuration.rollback()

        dev.close()


if __name__ == "__main__":
    """Main script execution.

    We will first load our inventory.yaml file into a new Python object `devices`
    Our main function will run next, which will take care of the templating
    and pushing of our configurations to the remote devices.
    """
    devices = inventory()
    main(devices)
