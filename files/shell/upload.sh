#!/usr/bin/bash

sshpass -p "juniper123" scp ../junos/generated/pe1.conf automation@100.123.0.11:/var/tmp/
sshpass -p "juniper123" scp ../junos/generated/p1.conf automation@100.123.0.12:/var/tmp/
sshpass -p "juniper123" scp ../junos/generated/pe2.conf automation@100.123.0.13:/var/tmp/
sshpass -p "juniper123" scp ../junos/generated/pe3.conf automation@100.123.0.14:/var/tmp/
sshpass -p "juniper123" scp ../junos/generated/p2.conf automation@100.123.0.15:/var/tmp/
sshpass -p "juniper123" scp ../junos/generated/pe4.conf automation@100.123.0.16:/var/tmp/
sshpass -p "juniper123" scp ../junos/generated/ce2.conf automation@100.123.0.17:/var/tmp/
sshpass -p "juniper123" scp ../junos/generated/ce1.conf automation@100.123.0.18:/var/tmp/
