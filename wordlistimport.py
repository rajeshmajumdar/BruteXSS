#! /usr/bin/env python

__author__ = 'Rajesh Majumdar'

def importword(file, lst):
    with open(file,'r') as f:
        for line in f:
            final = str(line.replace("\n",""))
            lst.append(final)
        return lst