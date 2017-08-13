# Stinker Defense Suite

SDS is an adaptive firewall and basic security suite for cloud
servers.

## Licensing

COPYING contains information about the GPL licence.
The SparForte documentation is located in the doc/ directory.

## Requirements

SDS is written in the SparForte language.
It requires SparForte 2.1.
It requires the Berkeley DB library.
It also requires a Bourne Compatible shell (e.g. bash).

The current version has been tested on CENTOS 7/Red Hat 7.

## Installation

Run the check security config script to check your server setup.

Edit the file config/config.inc.sp and customize the settings
to your system.

Run the sshd, mail and http daemons from cron.
TODO: there will be a master daemon to manage the smaller daemons.

