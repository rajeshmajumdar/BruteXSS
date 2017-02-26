#! /usr/bin/env python
__author__ = 'Rajesh Majumdar'

from urlparse import urlparse

def checkparams(url):
    params = urlparse(url)
    param = params.query
    #print param        #For testing
    if "=" in param:
        pstatus = "1"
    else:
        pstatus = "0"
    return pstatus

def getquery(url):
    #This function would return the query
    query = urlparse.query(url)
    squery = query.split("=")
    aquery = squery[1]
    return aquery