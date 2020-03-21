# Pystub
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/context:python)

[![Total alerts](https://img.shields.io/lgtm/alerts/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/alerts/)

Pystub is basic DNS stub server written in python with support for DNS over TLS.

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
- Implement importing ad blocking lists

# Testing
Shoutout to guyinatuxedo for their awesome DNS fuzzer: https://github.com/guyinatuxedo/dns-fuzzer
