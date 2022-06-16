## 📌 Overview

In hopes to making this project as easy as possible to execute, I have provided many tools to help with execution of the tasks within this project.

---

## Poetry

A [Poetry](https://python-poetry.org/docs/) lock file to help you create a Python environment that mirrors my own. As long as you [have Poetry installed on your machine](https://python-poetry.org/docs/), to you can simply type `poetry install` to create the virtual environment, followed by `poetry shell` to activate it.

---

## Invoke

You will find a packaged called [Invoke](http://www.pyinvoke.org/) installed within the virtual environment. Invoke is an elegant way to create CLI shortcuts for commands that are long to type out. Here is a short list of some of the Invoke operations created in the `tasks.py` file.

| Command            | Action                                              |
| ------------------ | --------------------------------------------------- |
| `invoke generate`  | Build the configurations locally with Jinaj2.       |
| `invoke configure` | Build and push our configurations with PyEZ.        |
| `invoke download`  | Download our configurations with PyEZ.              |
| `invoke rollback`  | Rollback to our bootstrap configurations with PyEZ. |
| `invoke validate`  | Validate our MPLS L3VPN circuit with JSNAPy.        |

---

## Dockerfile

A Dockerfile has also been provided for those that would like to execute this within an isolated container instead of a virtual environment. A couple of additional Invoke tasks are listed below to help with building and accessing the Docker container environment.

| Command        | Action                                                   |
| -------------- | -------------------------------------------------------- |
| `invoke build` | Build an instance of the Docker container image locally. |
| `invoke shell` | Get access to the BASH shell within our container.       |
