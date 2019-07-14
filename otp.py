#!/usr/bin/python3
import hashlib
import telnetlib
import re

def proof_of_work(part, compare):
    hex_str = '0123456789abcdef'
    for i in hex_str:
        for j in hex_str:
            for k in hex_str:
                for l in hex_str:
                    c = '%s%s%s%s' % (i,j,k,l) + part
                    if hashlib.sha256(c.encode('utf-8')).hexdigest() == compare:
                        return c

def try_hash(h):
    t = telnetlib.Telnet('localhost', 32173)

    powork = t.read_until(b'\n')

    v = re.search('\?\?\?\?(.*)\)', powork.decode('utf-8')).group(1)
    w = re.search('== (.*)\n', powork.decode('utf-8')).group(1)

    pow = proof_of_work(v, w)

    pow_in = pow + '\n'

    t.write(pow_in.encode('ascii'))

    t.read_until(b'\n')
    t.read_until(b'\n')
    t.read_until(b'\n')

    t.write('2\n'.encode('ascii'))

    htw = h + '\n'

    t.write(htw.encode('ascii'))
    result = t.read_all()
    return str(result)

def main():
    tv = "%s" % input("keep trying this value: ")
    h = hashlib.sha256(tv.encode('utf-8')).hexdigest()[0:17]
    print("Using: " + h)
    print("Waiting...")

    while True:
        result = try_hash(h)

        if "Invalid token" not in result:
            print("key: " + result)
            return

if __name__ == "__main__":
    main()
