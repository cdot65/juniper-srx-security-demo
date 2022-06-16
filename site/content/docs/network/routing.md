## 📌 Overview

This page explains elements of our generated routing configurations.

To best emulate a small ISP, I have opted to use OSPF between the MPLS routers, with external BGP peering with both customer connections.

PE routers do the heavy lifting in an MPLS environment, P routers are unaware of the L3VPN circuit and simply have to worry about forwarding based on MPLS labels.

We will reference the router PE1 for the examples below.

---

## OSPF

Our L3VPN circuit will be signaled with BGP, but we'll have to learn our BGP neighbor's loopback before we can form a BGP session with it. For this task we will use OSPF to share the loopbacks between our MPLS backbone.

On JunOS, we will simply enable the interface under an OSPF area within the `protocols` section of our configuration.

```
set protocols ospf area 0.0.0.0 interface ge-0/0/2.0 interface-type p2p
set protocols ospf area 0.0.0.0 interface ge-0/0/3.0 interface-type p2p
set protocols ospf area 0.0.0.0 interface lo0.0 passive
```

---

## eBGP to Customer1

We will form a external BGP session to our customer to exchange routing information with. Customer1's router `ce1` will not be MPLS aware, and will look extremely simple.

Our `pe1` configuration will find us creating a unique VRF routing instance for our neighbor. All BGP configuration for our neighbor will reside within this routing instance.

```
set routing-instances Customer1 instance-type vrf
set routing-instances Customer1 protocols bgp group Customer1 type external
set routing-instances Customer1 protocols bgp group Customer1 peer-as 65000
set routing-instances Customer1 protocols bgp group Customer1 neighbor 74.51.192.1
```

---

## iBGP to PE4

Every circuit needs to have a beginning and and end. From the perspective of `pe1`, it is the beginning and `pe4` will be the end of our L3 VPN circuit.

Internal BGP is the protocol used to signal L3VPN routing information between PE routers.

```
set protocols bgp group MPLS type internal
set protocols bgp group MPLS local-address 192.168.255.11
set protocols bgp group MPLS family inet-vpn unicast
set protocols bgp group MPLS peer-as 300
set protocols bgp group MPLS neighbor 192.168.255.16

```

We will specify our type of BGP as internal, and include the L3 VPN capability with `inet-vpn unicast`.
