## 📌 Overview

Our goal here is to use JSNAPy to validate the route table information within our provisioned fabric.

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

Our attention in this section will be upon the `validate.py` script and its associated JSNAPy test file `tests/test_l3vpn_routes.yaml`.

---

## 📝 Code Deep Dive

### Imports

Starting off with our imports, let's explain what we're bringing into this script and why.

```python
"""validate.py: use JSNAPy to validate the L3VPN circuit."""

import os

from jnpr.jsnapy import SnapAdmin

```

We see that we are bringing in the core python library `os`, this will be used very soon to help us figure out what the full path of our python script is.

Our additional import is pulling in `SnapAdmin` from the `jnpr.jsnapy` library. This will give us a JSNAPy object that will give us the necessary mechanisms to perform snapshots of our production network.

---

### Configurations

We will find a need to make adjustments to some of the default behavior of packages, and in some cases create an object to define some parameter.

---

#### JSNAPy parameters

Moving on to our configuration elements, let's briefly discuss what these objects do and why we've included them.

```python
PWD = os.path.dirname(os.path.realpath(__file__))

JSNAPY = SnapAdmin()

CONFIG = f"""
hosts:
  - device: 100.123.1.4
    username : automation
    passwd: juniper123
  - device: 100.123.1.7
    username : automation
    passwd: juniper123
tests:
  - {PWD}/tests/test_l3vpn_routes.yaml
"""
```

Remember when I mentioned the need to know the current working path of our python script? This is because we are creating an object called PWD, which will be equal to whatever path the script is executed from. If we executed this script from the `/home/skillet/` directory, the value of `PWD` would be `/home/skillet/`. This only matters because we'll need to point JSNAPy to the exact directory of our tests files, or else it'll fall back on the defaults.

We create an instance of the `SnapAdmin` object class we imported from JSNAPy, and we call the new object JSNAPY. From this point forward, when we want to perform a JSNAPy function, we will call this `JSNAPY` object created here.

Finally, our configuration file. This is a simple way of passing a YAML file into JSNAPy without needing an extra YAML file. We instead create a multi-line string in a new object called `CONFIG`, and within this string we have a YAML file contents. Since JSNAPy is expecting a configuration to be passed as a YAML file, this is a clever way of getting away with not needing another file.

---

#### JSNAPy Test File

With our attention now on the JSNAPy test file [https://github.com/cdot65/juniper-srx-security-demo/blob/main/files/python/tests/test_l3vpn_routes.yaml](`test_l3vpn_routes.yaml`), we will see that we are actually performing two seperate tests on both routers.

```yaml
{% raw %}
---
tests_include:
  - "route_table_bgp.l3vpn.0"
  - "route_table_Customer1.inet.0"
{% endraw %}
```

The `tests_include` statement allows us an easy way to bundle multiple tests within the same file. Make sure the name of the tests here match an actual test below.

---

Our first test will grab the XML output of the command `show route table bgp.l3vpn.0`, which is the L3VPN route table of a PE router.

```yaml
{% raw %}
route_table_bgp.l3vpn.0:
  - command: "show route table bgp.l3vpn.0"
  # - ignore-null: True
  - iterate:
      xpath: "//route-table"
      id: "./table-name"
      tests:
        - not-equal: "active-route-count, 0"
          info: "Validate active routes are found within the bgp.l3vpn.0 table"
          err: "Route table {{post['table-name']}} has zero active routes"
{% endraw %}
```

With the output captured, we iterate over all of the resulting routing tables (should be just 1), and test to see if the value of `active-route-count` is not equal to the number zero.

An informational message and error is provided if this route table exists and is currently zero.

> **Note**: the commented out `ignore-null: True` statement will let the test gracefully skip our assertion if the routing table is not found.

---

We perform a similar test with similar logic against the `Customer1.inet.0` routing table, which will make sure we have routes within the customer's VRF.

```yaml
{% raw %}
route_table_Customer1.inet.0:
  - command: "show route table Customer1.inet.0"
  # - ignore-null: True
  - iterate:
      xpath: "//route-table"
      id: "./table-name"
      tests:
        - not-equal: "active-route-count, 0"
          info: "Validate active routes are found within the Customer1.inet.0 table"
          err: "Route table {{post['table-name']}} has zero active routes"
{% endraw %}
```

---

### `main()`

This is the primary function of our script. Here will find us setting up our snapcheck to execute against our test file.

```python
if __name__ == "__main__":
    """Perform our JSNAPy tests."""
    JSNAPY.snapcheck(CONFIG, "test_l3vpn_routes")

```

There are thousands of explanations on `if __name__ == "__main__":` within Python, I will rely on your Google skills to find you the one that makes the most sense. In short, we need this so leave it alone.

We execute our JSNAPy task by calling our object called `JSNAPY`, asking it for the `snapcheck` method, and passing in our `CONFIG` object (really a multi-line YAML string), and a name for our tests.

This will execute JSNAPy with the parameters we have passed within our test file.

---

## 🚀 Workflow

Make sure your Python Virtual Environment has the necessary packages installed.

> **Reminder**: a [Poetry lock file has been provided](https://cdot65.github.io/juniper-srx-security-demo/docs/automation/poetry/) to help create your virtual environment to reflect ours. You will need to have [Poetry installed](https://python-poetry.org/).

Change into the `files/python` directory and execute the script

```bash
cd files/python
python validate.py
```

An alternative method of executing the script would be to leverage the Docker container provided with this project.

```bash
invoke validate
```

---

## 📸 Screenshots

![python validate.py](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/jsnapy_validate.png)

---

## 🐍 Script

```python
"""validate.py: use JSNAPy to validate the L3VPN circuit."""

import os

from jnpr.jsnapy import SnapAdmin

PWD = os.path.dirname(os.path.realpath(__file__))

JSNAPY = SnapAdmin()

CONFIG = f"""
hosts:
  - device: 100.123.1.4
    username : automation
    passwd: juniper123
  - device: 100.123.1.7
    username : automation
    passwd: juniper123
tests:
  - {PWD}/tests/test_l3vpn_routes.yaml
"""


if __name__ == "__main__":
    """Perform our JSNAPy tests."""
    JSNAPY.snapcheck(CONFIG, "test_l3vpn_routes")
```
