## 📌 Overview

This section explains our default IPv4 address schema

---

## IP Addressing

Each router will be given an ID of 11-17, and its loopback/router-id will be built upon it within the prefix of `192.168.255.{x}/32`, where `{x}` represents the local device's ID.

Additionally, P2P connections will follow a pattern of `10.{x}.{y}.{x}/24`, where `{x}` represents the local device's ID and `{y}` represents the ID of the remote router.

---

## Examples

Example files have been included to help explain

### Router1

```yaml
loopback0 = "192.168.255.11"
router id = "192.168.255.11"
p2p to router2 = "10.11.12.11/24"
p2p to router3 = "10.11.13.11/24"
p2p to router5 = "10.11.15.11/24"
```

### Router2

```yaml
loopback0 = "192.168.255.12"
router id = "192.168.255.12"
p2p to router2 = "10.11.12.12/24"
p2p to router3 = "10.12.13.12/24"
p2p to router5 = "10.12.15.12/24"
```
