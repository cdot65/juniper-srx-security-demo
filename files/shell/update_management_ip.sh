#!/bin/bash

ce1='100.255.1.0'
ce2='100.255.1.1'
p1='100.255.1.2'
p2='100.255.1.3'
pe1='100.255.1.4'
pe2='100.255.1.5'
pe3='100.255.1.6'
pe4='100.255.1.7'
pc1='100.255.35.2'
pc2='100.255.35.1'

# Update all of our files with the DHCP-assigned address found on the topology.

# CE1
sed -i "s/100.123.1.0/${ce1}/" ../python/production/vars/ce1.yaml
sed -i "s/100.123.1.0/${ce1}/" ../python/bootstrap/vars/ce1.yaml
sed -i "s/100.123.1.0/${ce1}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.0/${ce1}/" ../python/bootstrap/inventory.yaml

# CE2
sed -i "s/100.123.1.1/${ce2}/" ../python/production/vars/ce2.yaml
sed -i "s/100.123.1.1/${ce2}/" ../python/bootstrap/vars/ce2.yaml
sed -i "s/100.123.1.1/${ce2}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.1/${ce2}/" ../python/bootstrap/inventory.yaml

# P1
sed -i "s/100.123.1.2/${p1}/" ../python/production/vars/p1.yaml
sed -i "s/100.123.1.2/${p1}/" ../python/bootstrap/vars/p1.yaml
sed -i "s/100.123.1.2/${p1}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.2/${p1}/" ../python/bootstrap/inventory.yaml

# P2
sed -i "s/100.123.1.3/${p2}/" ../python/production/vars/p2.yaml
sed -i "s/100.123.1.3/${p2}/" ../python/bootstrap/vars/p2.yaml
sed -i "s/100.123.1.3/${p2}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.3/${p2}/" ../python/bootstrap/inventory.yaml

# PE1
sed -i "s/100.123.1.4/${pe1}/" ../python/production/vars/pe1.yaml
sed -i "s/100.123.1.4/${pe1}/" ../python/bootstrap/vars/pe1.yaml
sed -i "s/100.123.1.4/${pe1}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.4/${pe1}/" ../python/bootstrap/inventory.yaml

# PE2
sed -i "s/100.123.1.5/${pe2}/" ../python/production/vars/pe2.yaml
sed -i "s/100.123.1.5/${pe2}/" ../python/bootstrap/vars/pe2.yaml
sed -i "s/100.123.1.5/${pe2}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.5/${pe2}/" ../python/bootstrap/inventory.yaml

# PE3
sed -i "s/100.123.1.6/${pe3}/" ../python/production/vars/pe3.yaml
sed -i "s/100.123.1.6/${pe3}/" ../python/bootstrap/vars/pe3.yaml
sed -i "s/100.123.1.6/${pe3}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.6/${pe3}/" ../python/bootstrap/inventory.yaml

# PE4
sed -i "s/100.123.1.7/${pe4}/" ../python/production/vars/pe4.yaml
sed -i "s/100.123.1.7/${pe4}/" ../python/bootstrap/vars/pe4.yaml
sed -i "s/100.123.1.7/${pe4}/" ../python/production/inventory.yaml
sed -i "s/100.123.1.7/${pe4}/" ../python/bootstrap/inventory.yaml
