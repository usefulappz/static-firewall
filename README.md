# static-firewall
___
*Stateful, configurable iptables firewall for CentOS/Debian*

## Assumptions

This firewall was created with the intention of blocking all the things, including DHCP.  Configure this firewall carefully, and go through functions.sh before you start the service.

### Blackholed Networks

* 0.0.0.0
* 224.0.0.0/24

### Blackholed Services

* NetBIOS
* Dropbox

## Installation

To install, simply:

    git clone https://github.com/viralsecurity/static-firewall
    cd static-firewall
    sh installer.sh

## Post-Install

After static-firewall is installed, the installer will give you a list of files to edit, followed by a command to start up the firewall.

## Features

* Ingress and Egress catch-all logging
* SYNflood protection
* Commandline integration - *Type `firewall` or `sfw` to see available options*

## Philosophy

static-firewall uses a default-deny ruleset, which, when installed, will construct a list of listening TCP and UDP ports, and create exceptions for them in /etc/firewall/ports.ingress .  By default, resolvers in /etc/resolv.conf are added to egress trust automatically.  Rules in /etc/firewall/ports.egress are added to the OUTPUT chain, then logdrop for anything not in your rules attempting to egress your server.

