## 📌 Overview

This script is used when your goal is to just generate the configurations locally. PyEZ would not be the best candidate in this setup, as it's ability to generate template configurations is based upon a connection to a device.

Instead we will be using the same Jinja2 templating engine, just outside of PyEZ.

Configurations will be stored in a local directory, as declared within our script below.

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

Our attention in this section will be upon the `generate.py` script.

---

## 📝 Code Deep Dive

### Imports

We will be using the same `inventory.yaml` file used in our PyEZ configuration task, so we will need to import the ability to read YAML here.

```python
import yaml  # type: ignore
from jinja2 import Environment, FileSystemLoader
```

Jinja2 has a couple components that we'll use here,

- `Environment`: configuration options and template functionality
- `FileSystemLoader`: allows us to declare the path of our working directory

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

#### Output Directory

We will want to tell Jinja2 where we expect it to output the templated configurations. Setting it up here as a constant is simply out of convenience.

```python
CONFIG_PATH = "./configurations/generated"
```

---

#### Jinja2 Options

Jinja2 has many options, here we will just focus on some of the more common ones.

The `FileSystemLoader` was imported at the top of our script from Jinja2, and it will help us when writting to the local system. Its sole parameter passed references the path that Jinja2 should reference.

We create a new object called `env` and set it equal to an instance of the `Environment` class we imported from Jinja2, and passing it our recently-created `file_loader` object.

When autoescaping is enabled, Jinja2 will filter input strings to escape any HTML content submitted via template variables. Without escaping HTML input the application becomes vulnerable to Cross Site Scripting (XSS) attacks.

```python
file_loader = FileSystemLoader("./")
env = Environment(loader=file_loader, autoescape=True)
env.trim_blocks = True
env.lstrip_blocks = True
```

`trim_blocks`: If this is set to True the first newline after a block is removed.

`lstrip_blocks`: If this is set to True leading spaces and tabs are stripped from the start of a line to a block.

---

#### Device Variables

Jinja requires two things to complete its work: a template file and variables to run through it.

Here we will loop over the devices that are found within the `routers` group of our `inventory.yaml` file.

For each entry in our list, we will look for a variable file in the `vars/` directory. The name of the file will be based upon our device's hostname, which again was sourced from our `devices` object.

```python
for each in devices["routers"]:
    with open(f"vars/{each['name']}.yaml", "r") as stream:
```

The contents of our device's variables will be referenced as `stream` in the next steps below.

### `main()`

This is the primary function of our script. Here will find us setting up our Jinja2 environment and running our device's variable file through the configuration template.

When the `main` function is called in our `if __name__ == "__main__":` below, it will be passed the output of our `inventory` function described above. We will use this list of devices to loop over when generating our configurations.

```python
def main(devices):
```

---

#### Build configurations

With our device's configuration variables loaded into an object called `stream`, we will safely load the YAML file's contents into a python dictionary called `variables`.

Creating a new object called `template` and setting it equal an instance of Jinja2's `get_template()` method, and making sure to tell it where to find our template file.

Finally, we build our configuration by running our `variables` object through the `render` method, and storing the output as `output`.

```python
try:
    variables = yaml.safe_load(stream)
    template = env.get_template("templates/junos.j2")
    output = template.render(configuration=variables)

    # execution goes here.

except yaml.YAMLError as exc:
    print(exc)
```

We wrap this all up within a Try/Except clause, enabling us to halt execution and print a message when there's an error with our YAML

---

#### Writing to a local file

At this point, our generated configuration lives within Python as an object, this step will find us writing this to a local file.

We open a file for our device's configuration based upon its name, but we need to perform a little cleanup before we write anything.

A Jinja2 generated configuration will have a lot of blank lines for various reasons, we want to get rid of these blank lines to make it easier to read our configurations. So we loop over each line within our object and perform a `strip()` operation upon it.

Only lines with text within them will then be written to our file, with a `\n` to create a new line break after each line.

```python
with open(f"{CONFIG_PATH}/{each['name']}.conf", "w") as f:
    for line in output.splitlines():
        cleanedLine = line.strip()
        if cleanedLine:
            f.write(cleanedLine + str("\n"))
print(f"config built: {CONFIG_PATH}/{each['name']}.conf")
```

Finally we see a print statement on the console, informing us of our success and where to find the configurations.

---

### Initialize script

We will first load our inventory.yaml file into a new Python object `devices`.

Our main function will run next, which will take care of the templating a local copy of our configurations.

```python
if __name__ == "__main__":
    devices = inventory()
    main(devices)

```

---

## 🚀 Workflow

Make sure your Python Virtual Environment has the necessary packages installed.

> **Reminder**: a [Poetry lock file has been provided](https://cdot65.github.io/juniper-srx-security-demo/docs/automation/poetry/) to help create your virtual environment to reflect ours. You will need to have [Poetry installed](https://python-poetry.org/).

Change into the `files/python` directory and execute the script

```bash
cd files/python
python generate.py
```

An alternative method of executing the script would be to leverage the Docker container provided with this project.

```bash
invoke generate
```

---

## 📸 Screenshots

![python generate.py](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/generate.png)

---

## 🐍 Script

```python
"""Generate bootstrap configurations for our network devices."""
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

```

---
