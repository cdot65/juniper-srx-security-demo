"""Generate local configurations for our network devices."""
import yaml  # type: ignore
from jinja2 import Environment, FileSystemLoader

# define Jinja2 environment
CONFIG_PATH = "./configurations/generated"


def inventory():
    """Load our inventory.yaml into a python object called routers."""
    devices = yaml.safe_load(open("inventory.yaml"))
    return devices


def main(devices):
    """Template configuration with Jinja2 and store locally."""
    # set up our Jinja2 environment
    file_loader = FileSystemLoader("./")
    env = Environment(loader=file_loader, autoescape=True)
    env.trim_blocks = True
    env.lstrip_blocks = True

    # begin loop over devices
    for each in devices["routers"]:
        # create a template based on variables stored in file
        with open(f"vars/{each['name']}.yaml", "r") as stream:
            try:
                # set up  our environment and render configuration
                variables = yaml.safe_load(stream)
                template = env.get_template("templates/junos.j2")
                output = template.render(configuration=variables)

                # write our rendered configuration to a local file
                with open(f"{CONFIG_PATH}/{each['name']}.conf", "w") as f:
                    for line in output.splitlines():
                        cleanedLine = line.strip()
                        if cleanedLine:
                            f.write(cleanedLine + str("\n"))
                print(f"config built: {CONFIG_PATH}/{each['name']}.conf")  # noqa T001
            except yaml.YAMLError as exc:
                print(exc)  # noqa T001


if __name__ == "__main__":
    """Main script execution.

    We will first load our inventory.yaml file into a new Python object `devices`
    Our main function will run next, which will take care of the templating
    and pushing of our configurations to the remote devices.
    """
    devices = inventory()
    main(devices)
