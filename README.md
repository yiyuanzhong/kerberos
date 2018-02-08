# kerberos
kerberos is an integrated splash page server, which serves the splash page and the
authenticated page with its embedded httpd, and controls iptables internally.

The goal is to make an open hotspot with splash page without depending on any other
devices, while high security is still maintained by WPA2 enterprise, which means no
external radiusd nor authentication gateway.

Why
===
LEDE is big, mostly because the growing Linux kernel and OpenSSL.

Traditionally several packages must be installed to achieve this:
* freeradius (OpenSSL)
* hostapd
* wifidog
* wifidog-auth (nginx, PHP)

No, it won't fit at all.

What I actually did in Aptitude Adjustment is to implement a lightweight authentication
server with fastcgi that only does splash page, so it fit my TL-WR703N with 4M flash
while reserving 5 erase blocks (minimal requirement for jffs2):
* freeradius (OpenSSL)
* hostapd
* wifidog
* nginx
* spawn-fcgi
* kerberos (libfcgi)

And now with LEDE 17.01 the above packages can no longer fit. Tried many different ways
to shrink the image (removing unused dependencies from freeradius3, disabling OpenSSL
cipher suites, ...), still can't fit. So I have to rewrite kerberos completely:
* freeradius (OpenSSL)
* hostapd
* kerberos (libmicrohttpd)

Advantages
===
* One package to do everything
* Small footprint (~40K with libmicrohttpd-no-ssl)
* Only change your designated iptables chain, never mess others up
