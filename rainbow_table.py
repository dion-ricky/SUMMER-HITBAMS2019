#!/usr/bin/python3
import hashlib

for i in range(1, 100000000):
    print("%s:%s" % (hashlib.sha256(str(i).encode('utf-8')).hexdigest()[0:17],i))
