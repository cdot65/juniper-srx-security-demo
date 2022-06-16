## 📌 Overview

This script will be ran when you'd like to generate and push a device's configuration using PyEZ.

---

## 🐍 Files

Recall that all of our project's automation files are stored within the [files/python](https://github.com/cdot65/juniper-srx-security-demo/tree/main/files/python) directory.

```bash
files/python
├── configurations/
├── templates/
├── tests/
├── vars/
├── configure.py
├── download.py
├── generate.py
├── inventory.yaml
├── rollback.py
└── validate.py
```

Our attention in this section will be upon the `configure.py` script.

---

## 📝 Code Deep Dive

### Imports

We will be importing inventory data into our script from a local file named `inventory.yaml`, so we need to `import yaml` to handle this functionality.

```python
import yaml
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
```

Two primary functions of PyEZ will be imported, the first of which is the `Device` object. `Device` will allow us to model our device's parameters, things like IP address, username, and the sort. But `Device` will also enable us to build and maintain a NETCONF session to our remote device, so this object Class really does most of the heavy lifting here.

From the utilities module, we will be importing the `Config` class, which will (obviously) handle the configuration aspects of our script.

---

### Configurations

We will find a need to make adjustments to some of the default behavior of packages, and in some cases create an object to define some parameter.

---

#### Inventory

We are declaring our device inventory in a YAML markdown, since YAML is easy for humans and powerful for machines.

```python
def inventory():
    devices = yaml.safe_load(open("inventory.yaml"))
    return devices
```

Here we are taking advantage of the `yaml` library we imported and calling the `safe_load` method to load in the data from our `inventory.yaml` file.

The function returns our list of devices as an object called `devices`.

---

### `main()`

For our script's main function, we will loop over our list of routers that we imported from `inventory.yaml` to open a NETCONF session.

```python
def main(devices):
    for each in devices["routers"]:
        dev = Device(
            host=f"{each['ip']}",
            user="jcluser",
            password="Juniper!1",
            gather_facts=False,
        )
        dev.open()

```

After printing a status message to the console, we will be creating an empty dictionary called `data` and then stuffing our YAML vars into it as `data['configuration']`.

The only reason this is here is to help handle the fact that PyEZ and Jinja2 library load YAML vars differently than each other.

```python
print(f"connected to {each['name']}")

data = dict()
data["configuration"] = yaml.safe_load(open(f"vars/{each['name']}.yaml"))
```

---

We pass on the object that represents our device into the `Config` class, which will create a new object called `configuration` to represent our device's configuration.

```python
configuration = Config(dev)

configuration.load(
    template_path="templates/junos.j2", template_vars=data, format="set"
)
```

Next we see that we run the `load` method of our recently created `configuration` object, and we pass it three options:

1. Point to our Jinja2 template file at `templates/junos.j2`
2. Point to our device's variables (the `data` object created above)
3. Declare that our configuration is in the `set`format, alternatives would be `text`, `xml`, or `json`

This will push the device's configuration to the candidate config database, but will not commit it just yet.

---

We perform three functions upon the candidate configuration database:

1. Report any configuration diff to the console.
2. Perform a configuration check to make sure our generated configuration is valid.
3. Commit the configuration.

```python
configuration.pdiff()
if configuration.commit_check():
    configuration.commit()
else:
    configuration.rollback()

dev.close()
```

Should the configuration fail the configuration check, roll back to the previous state.

Close our NETCONF session.

---

### Initialize

There are thousands of explanations on `if __name__ == "__main__":` within Python, I will rely on your Google skills to find you the one that makes the most sense. In short, we need this so leave it alone.

```python
if __name__ == "__main__":
    devices = inventory()
    main(devices)

```

We will first load our inventory.yaml file into a new Python object `devices`.

Our main function will run next, which will take care of the templating and pushing of our configurations to the remote devices.

---

## 🚀 Workflow

Make sure your Python Virtual Environment has the necessary packages installed.

> **Reminder**: a [Poetry lock file has been provided](https://cdot65.github.io/juniper-srx-security-demo/docs/automation/poetry/) to help create your virtual environment to reflect ours. You will need to have [Poetry installed](https://python-poetry.org/).

Change into the `files/python` directory and execute the script

```bash
cd files/python
python configure.py
```

An alternative method of executing the script would be to leverage the Docker container provided with this project.

```bash
invoke configure
```

---

## 🐍 Script

```python
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

```

---

## 📸 Screenshots

![python validate.py](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/configure.png)
