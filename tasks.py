"""Tasks for use with Invoke.

(c) 2021 Calvin Remsburg
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os

from invoke import task  # type: ignore

# ---------------------------------------------------------------------------
# DOCKER PARAMETERS
# ---------------------------------------------------------------------------
DOCKER_IMG = "ghcr.io/cdot65/juniper-srx-security-demo"
DOCKER_TAG = "0.0.1"


# ---------------------------------------------------------------------------
# SYSTEM PARAMETERS
# ---------------------------------------------------------------------------
PWD = os.getcwd()


# ---------------------------------------------------------------------------
# CONSOLE MESSAGE TEMPLATE
# ---------------------------------------------------------------------------
def console_msg(message):
    """Provide a little formatting help for console messages."""
    print("-" * 78 + f"\n{message}\n" + "-" * 78 + "\n")  # noqa T001


# ---------------------------------------------------------------------------
# DOCKER CONTAINER BUILD
# ---------------------------------------------------------------------------
@task
def build(context):
    """Build an instance of the Docker container image locally."""
    console_msg("Build an instance of the Docker container image locally.")
    context.run(
        f"docker build -t {DOCKER_IMG}:{DOCKER_TAG} files/docker/",
    )


# ---------------------------------------------------------------------------
# DOCKER CONTAINER SHELL
# ---------------------------------------------------------------------------
@task
def shell(context):
    """Get access to the BASH shell within our container."""
    console_msg("Get access to the BASH shell within our container.")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files:/home/files \
            -w /home/files/ \
            --hostname l3vpn-demo \
            {DOCKER_IMG}:{DOCKER_TAG} /bin/bash",
        pty=True,
    )


# ---------------------------------------------------------------------------
# TESTS
# ---------------------------------------------------------------------------
@task
def bandit(context):
    """Check to see if there are any security issues with our code."""
    console_msg("test: bandit checking for security issues.")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/ \
            {DOCKER_IMG}:{DOCKER_TAG} bandit -r .",
        pty=True,
    )


@task
def black(context):
    """Enforce black style standards within our code."""
    console_msg("test: black standards enforcement.")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/ \
            {DOCKER_IMG}:{DOCKER_TAG} black .",
        pty=True,
    )


@task
def flake8(context):
    """Check to see if there are any formatting issues with our code."""
    console_msg("test: flake8 checking for formatting issues.")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/ \
            {DOCKER_IMG}:{DOCKER_TAG} flake8 .",
        pty=True,
    )


@task
def pydocstyle(context):
    """Check to see if there are any documentation issues with our code."""
    console_msg("test: pydocstyle checking for documentation issues.")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/ \
            {DOCKER_IMG}:{DOCKER_TAG} pydocstyle .",
        pty=True,
    )


@task
def yamllint(context):
    """Check to see if there are any YAML formatting issues with our code."""
    console_msg("test: yamllint checking for linting issues.")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/ \
            {DOCKER_IMG}:{DOCKER_TAG} yamllint .",
        pty=True,
    )


# ---------------------------------------------------------------------------
# USE Jinja2 TO BUILD CONFIGURATION AND STORE LOCALLY
# ---------------------------------------------------------------------------
@task
def generate(context):
    """Build the configurations locally with Jinaj2."""
    console_msg("Building the configuration locally with Jinaj2")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/python/ \
            {DOCKER_IMG}:{DOCKER_TAG} python generate.py",
        pty=True,
    )


# ---------------------------------------------------------------------------
# USE PyEZ TO BUILD CONFIGURATION AND PUSH TO DEVICES
# ---------------------------------------------------------------------------
@task
def configure(context):
    """Build and push our configurations with PyEZ."""
    console_msg("Build and push configurations to devices")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/python/ \
            {DOCKER_IMG}:{DOCKER_TAG} python configure.py",
        pty=True,
    )


@task
def download(context):
    """Download our configurations with PyEZ."""
    console_msg("Downloading our device configurations")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/python/ \
            {DOCKER_IMG}:{DOCKER_TAG} python download.py",
        pty=True,
    )


@task
def bootstrap(context):
    """Push our bootstrap configurations with PyEZ."""
    console_msg("Push bootstrap configurations to devices")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/eve-ng/bootstrap \
            {DOCKER_IMG}:{DOCKER_TAG} python bootstrap.py",
        pty=True,
    )


@task
def rollback(context):
    """Rollback to our bootstrap configurations with PyEZ."""
    console_msg("Rollback to our bootstrap configurations with PyEZ")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/python/ \
            {DOCKER_IMG}:{DOCKER_TAG} python rollback.py",
        pty=True,
    )


@task
def validate(context):
    """Validate our MPLS L3VPN circuit with JSNAPy."""
    console_msg("Validate our MPLS L3VPN circuit with JSNAPy")
    context.run(
        f"docker run -it --rm \
            -v {PWD}/files/:/home/files \
            -w /home/files/python/ \
            {DOCKER_IMG}:{DOCKER_TAG} python validate.py",
        pty=True,
    )
