## 📌 Overview

To get off the ground running with a local copy of this projects, start with making sure that you have the proper tools instead head of time.

> **Note: If you have EVE-NG running within your home, we have provided a [sample EVE-NG lab file](https://github.com/cdot65/juniper-srx-security-demo/tree/main/files/eve-ng).**

---

## Local Requirements

| Technology | Install Guide                                  |
| ---------- | ---------------------------------------------- |
| Docker     | [install](https://docs.docker.com/get-docker/) |
| Poetry     | [install](https://python-poetry.org/)          |

Please make sure you have correct permissions to execute

---

## Setting up the enviornment

Once you're ready for flight, start by [cloning](https://rogerdudler.github.io/git-guide/) this repository to your workstation.

```bash
git clone https://github.com/cdot65/juniper-srx-security-demo.git
```

![git clone](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/clone.png)

After changing into the project's directory, create and activate a virtual environment with Poetry

```bash
cd juniper-srx-security-demo.git
poetry install
poetry shell
```

![poetry install](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/poetry_install.png)

![poetry shell](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/poetry_shell.png)
