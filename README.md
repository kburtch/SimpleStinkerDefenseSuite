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
It requires SparForte 2.2.
It requires the Berkeley DB library.
It also requires a Bourne Compatible shell (e.g. bash).

The current version has been tested on CENTOS 7/Red Hat 7.

## Installation

Run the check security config script to check your server setup.

Edit the file config/config.inc.sp and customize the settings
to your system.

Select monitor\_mode if you want to test the software first.

Turn off your firewall, if you have one.
Run reset\_firewall to initialize the firewall.
Run the sshd, mail and http daemons on boot.
Run wash blocked -D from cron every hour or as often as needed.

e.g. in your crontab:
00      *      *      *      *     cd /root/ssds; /usr/local/bin/spar ssds_hourly.sp
50      00     *      *      *     cd /root/ssds; /usr/local/bin/spar ssds_daily.sp

Configure your log rotation software to rotate the log file.

/path-to-ssds/log/blocker.log {
    missingok
    notifempty
    create 0600 root root
    size 1M
    rotate 9
}

TODO: there will be a master daemon to manage the smaller daemons.

