#!/usr/bin/python
# Created: May 17, 2016
# Purpose: Get HTTP proxies from hidemyass

import requests
from bs4 import BeautifulSoup
import os

url1 = 'http://incloak.com/proxy-list/?maxtime=2000&type=h&anon=234#list'
url2 = 'http://free-proxy-list.net/'

def loadProxies(url, isurl2):  
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1'
        }
    r = requests.get(url, headers=headers)
    soup = BeautifulSoup(r.text, 'html.parser')
    if not isurl2:
        table = soup.find('table')
    else:
        table = soup.find('table', attrs={'id': 'proxylisttable'})
    datasets = []
    for row in table.find_all('tr')[1:]:
        data = row.find_all('td')
        try:
            ip = data[0].get_text()        
            port = data[1].get_text()
        except:
            continue
        if isurl2:
            anon = data[4].get_text().lower()
            if anon == 'transparent':
                continue
        datasets.append('%s:%s' % (ip, port))
    return datasets

proxies = loadProxies(url1, False)
proxies = proxies + loadProxies(url2, True)
try:
    os.remove('proxies')
except OSError:
    pass
with open('proxies', 'a+') as f:
    for proxy in proxies:
        f.write(proxy + '\n')
