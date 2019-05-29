# Simple Stinker Defense Suite

SSDS is an adaptive firewall and basic security suite for
Linux cloud servers.

## Licensing

COPYING contains information about the GPL licence.
The SSDS documentation is located in the doc/ directory.

## Summary

SSDS is a drop-in system providing baseline security services for
Linux cloud computers, giving adequate protection for most
businesses without requiring a lot of effort.

The SSDS firewall monitors a cloud server for incoming suspicious
activity and immediately disrupts the offending computer.  If there
is targetted activity against the computer, the offending computer
is banned for days or weeks.  This disrupts searches for
vulnerabilities on your server, stop DOS attacks and frees server
resources from dealing with these offenders.

Friendly or authorized computers can be whitelisted.  Unfriendly or
unauthorized servers can be blacklisted.

## Requirements

SSDS is written in the SparForte, a high-integrity language.
It requires SparForte 2.2.1.
It requires the Berkeley DB library.
It also requires a Bourne Compatible shell (e.g. bash).
The new dashboard web page requires xfvb (to render the graph) and imagemagik (to convert the graph to a web-friendly format).

The current version has been tested on CENTOS 7/Red Hat 7.

## Installation

Run the check security config script to check your server setup.

Edit the file config/config.inc.sp and customize the settings
to your system.

Select monitor\_mode if you want to test the software first.

Turn off your firewall, if you have one.
Run reset\_firewall to initialize the firewall.
Run the start\_ssds.sh script to start the sshd, mail and http daemons.  (Or run start\_ssds.sh on boot.)
Run the stop\_ssds.sh script to stop the sshd, mail and http daemons.

Install the hourly and daily tasks in your crontab.  For example:

00      *      *      *      *     cd /path-to-ssds; nice /usr/local/bin/spar ssds\_hourly.sp
50      00     *      *      *     cd /path-to-ssds; nice /usr/local/bin/spar ssds\_daily.sp

Configure your log rotation software to rotate the log file.

/path-to-ssds/log/blocker.log {
    missingok
    notifempty
    create 0600 root root
    size 1M
    rotate 9
}

