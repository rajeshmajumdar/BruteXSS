#! /usr/bin/env python
__author__ = 'Rajesh Majumdar'

import httplib
import socket
import urlparse

def checkurl(url, status):
    if "http://" in url:
        pass
    elif "https://" in url:
        pass
    else:
        url = "http://"+url
    finalurl = urlparse.urlparse(url)
    urldata = urlparse.parse_qsl(finalurl.query)
    domain0 = '{uri.scheme}://{uri.netloc}/'.format(uri=finalurl)
    domain = domain0.replace("https://","").replace("http://","").replace("www.","").replace("/","")
    try:
        request = httplib.HTTPConnection(domain)
        request.connect()
        status = "1"
    except (httplib.HTTPResponse):
        status = "0"
    return status
