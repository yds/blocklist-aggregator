'''Blocklist IPrange aggregator

Copyright © 2024-2025, Yarema <yds@Necessitu.de>

This software is open source.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''
from fabric import task
from invoke import Collection, Exit
from dns.resolver import resolve, NXDOMAIN
from urllib.request import urlopen
from socket import inet_aton
from calendar import timegm
from time import strptime, time
import yaml
import sys
import os
import re

ns = Collection()
cwd = os.getcwd()
encoding = 'utf-8'
verbose = {'verbose': 'show running tasks'}

def aton(addr):
    return inet_aton(addr.split('/')[0])

#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#
@task(help={'verbose': 'show discovered paths'})
def config(c, verbose=False):
    '''configure tasks environment'''
    if 'git' not in c: c.git = c.run('which git', hide=True, warn=True).stdout.strip()
    if 'sed' not in c: c.sed = c.run('which sed', hide=True, warn=True).stdout.strip() + ' -Ee'
    if 'curl' not in c: c.curl = c.run('which curl', hide=True, warn=True).stdout.strip() + ' -Rso'
    if 'fetch' not in c: c.fetch = c.run('which fetch', hide=True, warn=True).stdout.strip() + ' -qo'
    if 'pfctl' not in c: c.pfctl = c.run('which pfctl', hide=True, warn=True).stdout.strip()
    if 'iprange' not in c: c.iprange = c.run('which iprange', hide=True, warn=True).stdout.strip() + ' --optimize'
    if 'suricataupdate' not in c: c.suricataupdate = c.run('which suricata-update', hide=True, warn=True).stdout.strip() + ' --no-test'
    if 'updatelog' not in c: c.updatelog = '/var/log/suricata/update.log'
    if 'iprep' not in c: c.iprep = '/usr/local/etc/suricata/iprep/'
    if 'knowngood' not in c: c.knowngood = '/var/db/knowngood.cidr'
    if 'blocklist' not in c: c.blocklist = '/var/db/blocklist.cidr'
    if 'whitelists' not in c: c.whitelists = ['/var/db/whitelist*.cidr']
    if verbose:
        sys.stdout.write(yaml.dump(dict(c), default_flow_style=False, width=999, Dumper=yaml.CDumper))
ns.add_task(config)

@task(config, default=True, help=verbose)
def fetch(c, verbose=False):
    '''Fetch IP Reputation lists'''
    def fetch(lists, cidr, include=True):
        datadir = f'{cwd}/pass/' if include else f'{cwd}/drop/'
        os.makedirs(f'{datadir}', 0o755, exist_ok=True)
        for l in lists:
            lst = f"{datadir}{l['name']}.cidr"
            url = l['url']
            mtime = 60 * 60 * 24
            if 'interval' in l:
                mtime = str(l['interval'])
                if mtime.endswith('w'):     # Weeks
                    mtime = int(mtime[:-1]) * 60 * 60 * 24 * 7
                elif mtime.endswith('d'):   # Days
                    mtime = int(mtime[:-1]) * 60 * 60 * 24
                elif mtime.endswith('h'):   # Hours
                    mtime = int(mtime[:-1]) * 60 * 60
                elif mtime.endswith('m'):   # Minutes
                    mtime = int(mtime[:-1]) * 60
                else:                       # Seconds
                    mtime = int(mtime)
            if os.path.isfile(lst):
                mtime += os.path.getmtime(lst) - 30
            if time() > mtime:
                try:
                    if l['format'] == 'cidr':
                        c.run(f'{c.fetch} {lst} {url}', echo=verbose, pty=True)
                        if 'date' in l:
                            tag = f"# {l['date']['label']}"
                            fmt = l['date']['format']
                            with open(lst) as lst:
                                for mtime in lst:
                                    if mtime.startswith(tag):
                                        mtime = timegm(strptime(mtime.split(':',1)[1].strip(), fmt))
                                        os.utime(lst.name, (mtime, mtime))
                                        break
                    elif l['format'] == 'json':
                        data = yaml.load(urlopen(url).read().decode(encoding), Loader=yaml.CSafeLoader)
                        addrs = {}
                        table = data[l['table']] if 'table' in l else data[l['ipv4']]
                        for r in table:
                            if 'services' in l:
                                if r['service'] in l['services']:
                                    addr = r[l['ipv4']].strip()
                                    sep = '\t' if len(addr) > 15 else '\t\t'
                                    addrs[addr] = f"{sep}# {r['service']}"
                            else:
                                addrs[r.strip()] = ''
                        with open(lst, 'w') as lst:
                            for addr in sorted(addrs.keys(), key=aton):
                                print(f'{addr}{addrs[addr]}', file=lst)
                        if 'date' in l:
                            tag = l['date']['label']
                            fmt = l['date']['format']
                            mtime = timegm(strptime(data[tag], fmt))
                            os.utime(lst.name, (mtime, mtime))
                    elif l['format'] == 'regex':
                        data = urlopen(url).read().decode(encoding).split()
                        addrs = []
                        regex = re.compile(l['re'])
                        for r in data:
                            r = regex.match(r)
                            if r:
                                addrs.append(r.group(1))
                        with open(lst, 'w') as lst:
                            for addr in sorted(addrs, key=aton):
                                print(addr, file=lst)
                except:
                    continue
        include = ' ' if include else f' --except {c.knowngood} '
        c.run(f"{c.iprange} {datadir}*.cidr{include}{' '.join(c.whitelists)} > {cidr}", echo=verbose, pty=True)
    spf2cidr(c, verbose)
    whitelist(c, verbose)
    fetch(c.knowngoods, c.knowngood, True)
    fetch(c.blocklists, c.blocklist, False)
ns.add_task(fetch)

@task(config, help={'verbose': 'show SPF records and lookup errors'})
def spf2cidr(c, verbose=False):
    '''SPF hostnames to CIDR'''
    addrs = {}
    def resolvespf(host):
        try:
            answers = resolve(f'{host}.', 'TXT')
        except NXDOMAIN as e:
            if verbose:
                print(e, file=sys.stderr)
            return
        for rdata in answers:
            for spf in rdata.strings:
                spf = spf.decode(encoding)
                if spf.startswith('v=spf1 '):
                    if verbose:
                        sep = '\t' if len(host) > 15 else '\t\t'
                        print(f'{host}:{sep}{spf}')
                    for addr in spf.split():
                        if addr.startswith('ip4:') and '.' in addr:
                            addr = addr[4:].rstrip('.')
                            if len(addr.split('.')) > 2:
                                if len(addr.split('.')) == 3:
                                    addr = f'{addr}.0/24'
                                elif addr.endswith('/32'):
                                    addr = addr.split('/')[0]
                                addrs[addr] = host
                        elif addr.startswith('include:'):
                            resolvespf(addr[8:])
                        elif addr.startswith('redirect='):
                            resolvespf(addr[9:])
    hosts = f'{cwd}/whitelist.spf'
    if os.path.isfile(hosts):
        os.makedirs(f'{cwd}/pass', 0o755, exist_ok=True)
        mtime = os.path.getmtime(hosts)
        cidr = f'{cwd}/pass/SPF.cidr'
        if not os.path.isfile(cidr) or os.path.getmtime(cidr) < mtime:
            with open(hosts) as hosts:
                for host in hosts:
                    resolvespf(host.strip())
            with open(cidr, 'w') as cidr:
                for addr in sorted(addrs.keys(), key=aton):
                    sep = '\t' if len(addr) > 15 else '\t\t'
                    print(f'{addr}{sep}# {addrs[addr]}', file=cidr)
            os.utime(cidr.name, (mtime, mtime))
ns.add_task(spf2cidr)

@task(config, help=verbose)
def whitelist(c, verbose=False):
    '''whitelist.txt with IPs and/or hostnames to CIDR'''
    lst = f'{cwd}/whitelist.txt'
    if not os.path.isfile(lst) and 'whitelist' in c:
        c.run(f'{c.fetch} {lst} {c.whitelist}', echo=verbose, pty=True)
    if os.path.isfile(lst):
        os.makedirs(f'{cwd}/pass', 0o755, exist_ok=True)
        mtime = os.path.getmtime(lst)
        cidr = f'{cwd}/pass/WhiteList.cidr'
        if not os.path.isfile(cidr) or os.path.getmtime(cidr) < mtime:
            with open(cidr, 'w') as cidr:
                hide = not verbose
                for addr in c.run(f'{c.iprange} {lst} 2>/dev/null', echo=verbose, hide=hide, warn=True, pty=True).stdout.split():
                    if addr not in ('0.0.0.0','255.255.255.255'):
                        print(addr, file=cidr)
            os.utime(cidr.name, (mtime, mtime))
ns.add_task(whitelist)

@task(fetch, help=verbose)
def pfreplace(c, verbose=False):
    '''Repalce PF tables'''
    quiet = '' if verbose else ' -q'
    c.run(f'{c.pfctl}{quiet} -t knowngood -T replace -f {c.knowngood}', echo=verbose, pty=True)
    c.run(f'{c.pfctl}{quiet} -t blocklist -T replace -f {c.blocklist}', echo=verbose, pty=True)
ns.add_task(pfreplace)

@task(config, help=verbose)
def suricataupdate(c, verbose=False):
    '''Update IP Reputation lists'''
    DROP = 0
    PASS = 1
    SCORE = 100
    os.makedirs(f'{c.iprep}', 0o755, exist_ok=True) # /usr/local/etc/suricata/iprep/
    c.whitelists.append(c.knowngood)
    c.run(f"{c.iprange} {cwd}/pass/*.cidr {' '.join(c.whitelists)} | {c.sed} 's/^(.*)/\\1,{PASS},{SCORE}/' > {c.iprep}pass.list", echo=verbose, pty=True)
    c.run(f"{c.iprange} {cwd}/drop/*.cidr --except {' '.join(c.whitelists)} | {c.sed} 's/^(.*)/\\1,{DROP},{SCORE}/' > {c.iprep}drop.list", echo=verbose, pty=True)
    c.run(f"{c.suricataupdate} >{c.updatelog} 2>/dev/null", echo=verbose, pty=True)
ns.add_task(suricataupdate)

@task(config, help={'verbose': 'show deleted CIDRs'})
def clean(c, verbose=False):
    '''Delete all CIDRs'''
    rmfr = f'rm -vfr {cwd}/drop {cwd}/pass'
    if verbose:
        c.run(rmfr, echo=verbose, pty=True)
    else:
        sys.exit(f'\n\tRun `inv clean --verbose` to delete all CIDRs for real:\n\n\t{rmfr}\n')
ns.add_task(clean)

#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#===#
