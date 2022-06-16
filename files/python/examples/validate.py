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
