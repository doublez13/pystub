all:
        make -f /usr/share/selinux/devel/Makefile pystub.pp
install:
        /usr/sbin/semodule -i pystub.pp
clean:
        /usr/sbin/semodule -r pystub
