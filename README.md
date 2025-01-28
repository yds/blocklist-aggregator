# Blocklist IPrange compiler

## What does it do?

This is a set of [Python][]/[Invoke][] tasks to download a collection
of public blacklists and public whitelists to be used in a firewall.

## How to use it

Pick a working directory where to install these [Invoke][] tasks.
e.g. `/etc/iprange/` or `/var/db/ipf/`

Install by cloning the repo:
```sh
git clone https://github.com/yds/blocklist-compiler.git /var/db/ipf
```
Change `/var/db/ipf/` in the above command to whatever directory
makes sense to you on *your* system, this HowTo will assume that's
the directory where these scripts are installed.

Review and edit the `invoke.yml` configuration file:
- `blocklist`: location of the `blocklist.cidr` file loaded by the packet filter.
- `knowngood`: location of the `knowngood.cidr` file loaded by the packet filter.
- `updatelog`: location of the `update.log` file for `suricata-update` output.
- `iprep`: location of the [Suricata][] IP reputation directory.
- `blacklists`: list of additional local blacklist CIDR files.
- `whitelists`: list of additional local whitelist CIDR files.
- `knowngoods`: list of public whitelists to download.
- `blocklists`: list of public blacklists to download.
- `zzz_disabled`: list of inactive, disabled list definitions stashed out of the way for reference.
- `whitelist`: URL of a sample `whitelist.txt` file to download if a local file cannot be found.

**IMPORTANT**: create a `whitelist.cidr` file with all the IP ranges
which you **NEVER** want blocked. Include [RFC1918][] address
ranges and any IP address ranges assigned to you by your ISP.

The `invoke.yml` configuration file has default settings to include
any local `blacklist*.cidr` and `whitelist*.cidr` wildcard files
it can find. Create or symlink any additional files fitting the
wildcard naming pattern as needed.

Edit `/etc/pf.conf` and add the tables and rules managed by the `pfreplace` task:
```
table <blocklist> counters persist file "/var/db/ipf/blocklist.cidr"
table <knowngood> counters persist file "/var/db/ipf/knowngood.cidr"

# example rdr using the <blocklist> and <knowngood> tables with OpenBSD's spamd(8)
rdr pass on wan0 proto tcp from { <blocklist> <spamd> !<knowngood> !<spamd-white> } to port smtp -> (lo0:0) port spamd

# example block rule to drop all <blocklist> attack traffic
block drop in quick on wan0 from <blocklist> label "block attack traffic"
```

Edit and install the `crontab` file to `/usr/local/etc/cron.d/blocklist`:
```crontab
*/5	*	*	*	*	root	cd /var/db/ipf && /usr/local/bin/invoke pfreplace
31	0	*	*	*	root	cd /var/db/ipf && /usr/local/bin/invoke suricataupdate
```
Skip `suricataupdate` in your crontab if not needed. `pfreplace`
can be replaced with `fetch` to download and compile the blacklists
and whitelists without loading them into the packet filter.

The `fetch` task is smart enough to not download any public lists
more often than the `interval` setting allows. Some blacklists are
updated as often as every 5 minutes e.g. [NUBI][], or every hour e.g.
[CINS Army][], but most are updated no more often than once a day.
The `interval` setting defaults to 24 hours if missing in the list
definition.

It does not make sense to run the `fetch` task more often than every
5 minutes. Running less often than every 5 minutes is fine.

## [Invoke][] tasks

All tasks have a `--verbose` parameter to display the output of
what is getting done. The `clean` task _requires_ the `--verbose`
parameter to actually delete all the files and directories created
by the other tasks.

- `inv config --verbose`: displays the loaded configuration.
- `inv fetch --verbose`: downloads the IP reputation lists.
- `inv spf2cidr --verbose`: looks up the DNS TXT/SPF records
  for all the senders in the `whitelist.spf` file to add to
  the `knowngood.cidr` output.
- `inv whitelist --verbose`: process the `whitelist.txt` file
  to a CIDR list. This file can be a mix of hostnames,
  IP addresses or CIDRs.
- `inv pfreplace --verbose`: `pfctl` replace the `knowngood`
  and `blocklist` tables with new CIDRs.
- `inv suricataupdate --verbose`: compile the downloaded
  IP reputation lists into [Suricata][] IP reputation format
  CSV files and perform a full [Suricata][] update.
- `inv clean --verbose`: delete all the files created for
  compiling the output CIDR lists.

DNS lookups tend to be slow therefore `whitelist.spf` and `whitelist.txt`
are processed only when the timestamp of the files changes.

## Requirements and dependencies

On [FreeBSD][] the following ports/pkgs are required:
- [lang/python3](https://Python.org/ "Python is a programming language that lets you get shite done!"): Meta-port for the Python interpreter 3.x
- [devel/py-invoke](https://PyInvoke.org/ "Invoke is a Python library for managing shell-oriented subprocesses and organizing executable Python code into CLI-invokable tasks."): Python task execution tool and library
- [devel/py-fabric](https://FabFile.org/ "Fabric is a high level Python library designed to execute shell commands remotely over SSH."): High level SSH command execution
- [devel/py-pyyaml](https://PyYAML.org/ "YAML Ain't Markup Language"): Python YAML parser
- [net-mgmt/iprange](https://GitHub.com/firehol/iprange "IP ranges management tool"): IP ranges management tool

The following ports/pkgs are optional:
- [security/suricata](https://Suricata.io/ "High Performance Network IDS, IPS and Security Monitoring engine"): High Performance Network IDS, IPS and Security Monitoring engine
- [ftp/curl](https://cURL.se/ "Command line tool and library for transferring data with URLs"): Command line tool and library for transferring data with URLs

## Misc Notes

The sample `whitelist.txt` file is downloaded from the [MalTrail][]
malicious traffic detection system. Definitely look over the content
and remove anything you do not need whitelisted.

Before enabling the `blocklist` in the packet filter run `inv fetch`
and ensure that everything you need whitelisted is indeed in the
`knowngood.cidr` output file and search the generated `blocklist.cidr`
file to ensure nothing you need whitelisted ends up in the `blocklist`.

## Linux

To use [curl](https://cURL.se/ "Command line tool and library for transferring data with URLs")
instead of [FreeBSD][]'s `fetch(1)` add the following line to `invoke.yml`:
```yaml
fetch: /usr/local/bin/curl -Rso
```
adjust the path above to `/usr/bin/curl` and with a few other path
tweaks the `fetch` and `suricataupdate` tasks should work on Linux.

## License

See [LICENSE](https://GitHub.com/yds/blocklist-compiler/blob/master/LICENSE "BSD3CLAUSE").

[FreeBSD]:https://FreeBSD.org/ "The Power to Serve"
[PyYAML]:http://www.PyYAML.org/ "YAML Ain't Markup Language"
[Python]:https://Python.org/ "Python is a programming language that lets you get shite done!"
[Invoke]:https://PyInvoke.org/ "Invoke is a Python library for managing shell-oriented subprocesses and organizing executable Python code into CLI-invokable tasks."
[Fabric]:https://FabFile.org/ "Fabric is a high level Python library designed to execute shell commands remotely over SSH."
[Suricata]:https://Suricata.io/ "High Performance Network IDS, IPS and Security Monitoring engine"
[MalTrail]:https://GitHub.com/stamparm/maltrail "Maltrail is a malicious traffic detection system"
[RFC1918]:https://www.RFC-Editor.org/rfc/rfc1918 "Address Allocation for Private Internets"
[CINS Army]:https://CINSarmy.com/list-download/ "Collective Intelligence Network Security"
[NUBI]:https://www.NUBI-Network.com/faq.php "NUBI was designed to be a replacement for the venerable BadIPs.com after their website went offline in late 2020."
