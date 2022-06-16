#!/usr/bin/bash

sshpass -p "juniper123" scp automation@100.123.0.11:/var/tmp/config.conf ../junos/downloaded/pe1.conf
sshpass -p "juniper123" scp automation@100.123.0.12:/var/tmp/config.conf ../junos/downloaded/p1.conf
sshpass -p "juniper123" scp automation@100.123.0.13:/var/tmp/config.conf ../junos/downloaded/pe2.conf
sshpass -p "juniper123" scp automation@100.123.0.14:/var/tmp/config.conf ../junos/downloaded/pe3.conf
sshpass -p "juniper123" scp automation@100.123.0.15:/var/tmp/config.conf ../junos/downloaded/p2.conf
sshpass -p "juniper123" scp automation@100.123.0.16:/var/tmp/config.conf ../junos/downloaded/pe4.conf
sshpass -p "juniper123" scp automation@100.123.0.17:/var/tmp/config.conf ../junos/downloaded/ce2.conf
sshpass -p "juniper123" scp automation@100.123.0.18:/var/tmp/config.conf ../junos/downloaded/ce1.conf
