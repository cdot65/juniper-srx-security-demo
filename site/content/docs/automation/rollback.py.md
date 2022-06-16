## 📌 Overview

This script will be ran when you'd like to use PyEZ to roll a device's configuration back to the previous configuration.

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

Our attention in this section will be upon the `rollback.py` script.

---

## 📝 Code Deep Dive

### Imports

We will be importing inventory data into our script from a local file named `inventory.yaml`, so we need to `import yaml` to handle this functionality.

```python
import yaml
from jnpr.junos import Device
from jnpr.junos.exception import CommitError
from jnpr.junos.exception import ConnectError
from jnpr.junos.exception import LockError
from jnpr.junos.exception import RpcError
from jnpr.junos.exception import UnlockError
from jnpr.junos.utils.config import Config
```

Two primary functions of PyEZ will be imported, the first of which is the `Device` object. `Device` will allow us to model our device's parameters, things like IP address, username, and the sort. But `Device` will also enable us to build and maintain a NETCONF session to our remote device, so this object Class really does most of the heavy lifting here.

From the utilities module, we will be importing the `Config` class, which will (obviously) handle the configuration aspects of our script.

Several problems could arise within this request, so we import PyEZ's error types to help us validate that everything either worked or failed safely.

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
        try:
            dev.open()
            print(f"connected to {each['name']}")
        except ConnectError as err:
            print(f"Cannot connect to {each['name']}: {err}")
            return
```

Create an object based on the `Config` object type, passing it our connection to the device.

Perform a lock on the configuration database, perform the rollback, and commit.

```python

        configuration = Config(dev)

        print("Locking the configuration")
        try:
            configuration.lock()
        except LockError as err:
            print(f"Unable to lock configuration: {err}")
            dev.close()
            return
        try:
            print("Rolling back the configuration")
            configuration.rollback(rb_id=1)
            print("Committing the configuration")
            configuration.commit()
        except CommitError as err:
            print(f"Error: Unable to commit configuration: {err}")
        except RpcError as err:
            print(f"Unable to roll back configuration changes: {err}")

        print("Unlocking the configuration")
        try:
            configuration.unlock()
        except UnlockError as err:
            print(f"Unable to unlock configuration: {err}")
        dev.close()
```

Unlock the configuration database and close our NETCONF session.

---

### Initialize script

There are thousands of explanations on `if __name__ == "__main__":` within Python, I will rely on your Google skills to find you the one that makes the most sense. In short, we need this so leave it alone.

```python
if __name__ == "__main__":
    devices = inventory()
    main(devices)

```

We will first load our inventory.yaml file into a new Python object `devices`.

Our main function will run next, which will take care of the logging into and performing a rollback upon the remote devices.

---

## 🚀 Workflow

Make sure your Python Virtual Environment has the necessary packages installed.

> **Reminder**: a [Poetry lock file has been provided](https://cdot65.github.io/juniper-srx-security-demo/docs/automation/poetry/) to help create your virtual environment to reflect ours. You will need to have [Poetry installed](https://python-poetry.org/).

Change into the `files/python` directory and execute the script

```bash
cd files/python
python rollback.py
```

An alternative method of executing the script would be to leverage the Docker container provided with this project.

```bash
invoke rollback
```

---

## 📸 Screenshots

![python rollback.py](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/rollback.png)

---

## 🐍 Script

```python
"""rollback.py: perform a 'rollback 1' operation on our network devices."""
import yaml  # type: ignore
from jnpr.junos import Device  # type: ignore
from jnpr.junos.exception import CommitError  # type: ignore
from jnpr.junos.exception import ConnectError  # type: ignore
from jnpr.junos.exception import LockError  # type: ignore
from jnpr.junos.exception import RpcError  # type: ignore
from jnpr.junos.exception import UnlockError  # type: ignore
from jnpr.junos.utils.config import Config  # type: ignore


def inventory():
    """Load our inventory.yaml into a python object called routers."""
    devices = yaml.safe_load(open("inventory.yaml"))
    return devices


def main(devices):
    """Rollback the configuration to the previous state.

    Loop over our list of routers that we imported from inventory.py
    Utilize the ID as the last octet within the IP address of the router
    Once the connection is open, perform the following steps

    1. Print a message to the console
    2. Perform a "lock" on the configuration
    3. Rollback to the previous state
    4. Commit the configuration
    5. Perform an "unlock" on the configuration
    6. Gracefully exit the NETCONF session

    Various error handling mechanisms have been included to ensure that
    the operator safely exits the script when a known failure occurs.
    """
    for each in devices["routers"]:
        dev = Device(
            host=f"{each['ip']}",
            user="jcluser",
            password="Juniper!1",
            gather_facts=False,
        )
        try:
            dev.open()
            print(f"connected to {each['name']}")  # noqa T001
        except ConnectError as err:
            print(f"Cannot connect to {each['name']}: {err}")  # noqa T001
            return

        configuration = Config(dev)

        # Lock the configuration
        print("Locking the configuration")  # noqa T001
        try:
            configuration.lock()
        except LockError as err:
            print(f"Unable to lock configuration: {err}")
            dev.close()
            return
        try:
            print("Rolling back the configuration")  # noqa T001
            configuration.rollback(rb_id=1)
            print("Committing the configuration")  # noqa T001
            configuration.commit()
        except CommitError as err:
            print(f"Error: Unable to commit configuration: {err}")  # noqa T001
        except RpcError as err:
            print(f"Unable to roll back configuration changes: {err}")  # noqa T001

        print("Unlocking the configuration")  # noqa T001
        try:
            configuration.unlock()
        except UnlockError as err:
            print(f"Unable to unlock configuration: {err}")  # noqa T001
        dev.close()


if __name__ == "__main__":
    """Main script execution.

    We will first load our inventory.yaml file into a new Python object `devices`
    Our main function will run next, which will take care of the rolling back the
    configurations on the remote devices.
    """
    devices = inventory()
    main(devices)
```

---
