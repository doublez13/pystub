# Pystub
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/context:python)

[![Total alerts](https://img.shields.io/lgtm/alerts/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/alerts/)

Pystub is a small DNS stub server written in python with support for DNS over TLS.  
Pystub also allows importing domain blocklists. In the settings.py file, you can specify a list of domains to be blacklisted, or point to a url that contains a list of domains. This feature can be used to block ad servers or other invasive content.

# Running
Pystub needs permission to bind on port 53.
This can be achieved with CAP_NET_BIND_SERVICE
```
# /path/to/pystub
```

# Upstream transports
- UDP
- TCP
- TLS

# Record Support
Support for the following record types has been implemented with more to come soon:
- A
- NS
- CNAME
- SOA
- PTR
- MX
- TXT
- AAAA
- SRV

# TODO:
- RFC 1035 compliance
- Share upstream TCP sockets
- Run as daemon
- Implement optional caching

# Thanks
Thanks to Peter Lowe for maintaining a fantastic blocklist for ad servers: https://pgl.yoyo.org/as/  
Shoutout to guyinatuxedo for their awesome DNS fuzzer: https://github.com/guyinatuxedo/dns-fuzzer
