# Pystub
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/context:python) 
[![Total alerts](https://img.shields.io/lgtm/alerts/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/alerts/) 
![GitHub](https://img.shields.io/github/license/doublez13/pystub)

Pystub is a small DNS resolver written in python with support for DNS over TLS and ad blocking.  
In the settings.py file, you can specify a list of domains to be blacklisted, or point to a url that contains a list of domains. This feature can be used to block ad servers or other invasive content.

## Getting Started
### Installing
To install Pystub, run the `install.sh` script. This script installs the Pystub executable, the Pystub configuration file, and a Pystub Systemd unit file.

### Configuration
By default, Pystub looks for the pystub.yml configuration file at `/etc/pystub.yml`. This can be overridden with the -C flag.
```
# /path/to/pystub -C /path/to/pystub.yml
```

### Socket
By default, Pystub binds to 127.0.0.1:53. This can be modified by changing the `listen` parameter in the `pystub.yml` file. If left blank, Pystub will bind to all IPs on port 53. If you'd prefer not to run Pystub as root, you can grant the CAP_NET_BIND_SERVICE capability. This is how the service file is configured.

### Running as a service
The Systemd unit file is configured to run Pystub as a dynamic (sandboxed) user, with `CAP_NET_BIND_SERVICE` granted in order to bind to port 53.    
```
# systemctl start pystub
```
## Ad Blocking
Domains can be blocked under the blacklist sections of the `pystub.yml` file. Adding a domain to the `domain` section ensures that any request for this domain or subdomains will be blocked. Additionally, an entry can be added the `url` section that points to a list of domains to be blocked. The example configuration file should be enough to block most ads.   

To see a list of domains that are blocked in real time, you can start Pystub with the `-v` flag.
```
# /path/to/pystub -v 
Imported 3278 blacklist domains
Server listening on 127.0.0.1 port 53

Blocked: match.adsrvr.org
Blocked: api.rlcdn.com
Blocked: cdn.branch.io
Blocked: 5165526.fls.doubleclick.net
Blocked: static.ads-twitter.com
Blocked: www.googletagmanager.com
Blocked: dpm.demdex.net
Blocked: c.amazon-adsystem.com
Blocked: secure-us.imrworldwide.com
Blocked: cdn.keywee.co
Blocked: cdn.adsafeprotected.com
Blocked: cdn.krxd.net
Blocked: securepubads.g.doubleclick.net
Blocked: srv-2020-04-01-16.config.parsely.com
Blocked: as-sec.casalemedia.com
Blocked: nba.demdex.net
Blocked: sb.scorecardresearch.com
Blocked: js-agent.newrelic.com
Blocked: www.googleadservices.com
Blocked: ad.doubleclick.net
Blocked: cdn3.optimizely.com
Blocked: www.summerhamster.com
```

## Upstream transports
- UDP
- TCP
- TLS

## Record Support
Support for the following record types has been implemented. If you need additional queries implemented, open an issue and I'll check it out.
- A
- NS
- CNAME
- SOA
- PTR
- MX
- TXT
- AAAA
- SRV
- SSHFP

## TODO
- RFC 1035 compliance
- Share upstream TCP sockets
- Implement optional caching

## License
This project is licensed under the 2-Clause BSD License.

## Acknowledgements
Thanks to Peter Lowe for maintaining a fantastic blocklist for ad servers: https://pgl.yoyo.org/as/  
Shoutout to guyinatuxedo for their awesome DNS fuzzer: https://github.com/guyinatuxedo/dns-fuzzer
