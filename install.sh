#!/usr/bin/env sh
install -v -m 755 pystub /usr/bin/pystub
install -v -m 644 pystub.yml /etc/pystub.yml
if [ -d "/etc/systemd/system" ]
then
    install -v -m 644 pystub.service /etc/systemd/system/pystub.service
fi
