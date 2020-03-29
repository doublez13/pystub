# Pystub
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/context:python) 
[![Total alerts](https://img.shields.io/lgtm/alerts/g/doublez13/pystub.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/doublez13/pystub/alerts/) 
![GitHub](https://img.shields.io/github/license/doublez13/pystub)

Pystub is a small DNS stub server written in python with support for DNS over TLS.  
Pystub also allows importing domain blocklists. In the settings.py file, you can specify a list of domains to be blacklisted, or point to a url that contains a list of domains. This feature can be used to block ad servers or other invasive content.

## Getting Started
By default, Pystub binds to 127.0.0.1:53. This can be modified by changing the `listen` parameter in the pystub.yml file. If left blank, Pystub will bind to all IPs on port 53.

### Running as a service
To install Pystub, run the install.sh script. This script installs Pystub, the Pystub configuration file, and a Pystub Systemd unit file. The Systemd unit file is configured to run Pystub as a dynamic (sandboxed) user, with CAP_NET_BIND_SERVICE granted in order to bind to port 53   
```
# ./install.sh
# systemctl start pystub
```
### Running manually  
Pystub needs permission to bind on port 53.
This can be achieved with CAP_NET_BIND_SERVICE if you'd rather not run Pystub as root.
```
# /path/to/pystub -C /path/to/pystub.yml
```

## Upstream transports
- UDP
- TCP
- TLS

## Record Support
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
- SSHFP

## TODO
- RFC 1035 compliance
- Share upstream TCP sockets
- Implement optional caching

## License
This project is licensed under the 2-Clause BSD License

## Acknowledgements
Thanks to Peter Lowe for maintaining a fantastic blocklist for ad servers: https://pgl.yoyo.org/as/  
Shoutout to guyinatuxedo for their awesome DNS fuzzer: https://github.com/guyinatuxedo/dns-fuzzer
