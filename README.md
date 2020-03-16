# Pystub
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

#TODO:
- RFC 1035 compliance
- Improve crash prevention in main
- Add support for more record types
- Multithread the sockets
- Run as daemon

# Testing
Shoutout to guyinatuxedo for their awesome DNS fuzzer: https://github.com/guyinatuxedo/dns-fuzzer
