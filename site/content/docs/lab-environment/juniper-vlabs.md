## 📌 Overview

If you're interested in using your access to Juniper's vLabs, we have provided a blueprint named [Automation Python MPLS L3VPN](https://portal.cloudlabs.juniper.net/RM/Diagram/Index/74601771-360a-4d01-80c9-c1f41f5d2438?diagramType=Topology)

![git clone](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/vlabs.png)

Log into Juniper vLabs in your web browser and visit the [blueprint](https://portal.cloudlabs.juniper.net/RM/Diagram/Index/74601771-360a-4d01-80c9-c1f41f5d2438?diagramType=Topology).

Reserve it for as much time as you need

![juniper vlabs reserve](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/vlabs_reserve.png)

When your topology is up and running, we'll focus our attention on the server labeled "Automation". Hover your mouse over the server and a pop-up menu will appear.

![juniper vlabs ssh](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/vlabs_automation_ssh.png)

Selecting SSH from the menu will find your browser jumping into an SSH session with the server.

![juniper vlabs server](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/vlabs_automation_server.png)

Change into the directory container our project, and perform a `git pull` operation to make sure you're using the latest copy. There will be a lot of updates, don't worry if the screen fills up.

```bash
cd automation/juniper-srx-security-demo
git pull
```

![git pull](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/git_pull.png)

Activate your Python virtual environment by typing `poetry shell`, follow it with a `which python` to make sure your python execution path has been updated.

```bash
poetry shell
```

![poetry shell](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/vlabs_poetry_shell.png)

Before moving on to Invoke, let's compare our inventory file with that of vLabs topology. Make any necessary changes before executing.

```bash
cat files/python/inventory.yaml
```

![poetry shell](https://raw.githubusercontent.com/cdot65/juniper-srx-security-demo/dev/site/content/assets/images/vlabs_inventory.png)
