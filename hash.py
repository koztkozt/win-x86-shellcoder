#!/usr/bin/python3
import sys
import argparse
import ctypes, struct, numpy
import keystone as ks


def to_hex(s):
    retval = list()
    for char in s:
        retval.append(hex(ord(char)).replace("0x", ""))
    return "".join(retval)


def to_sin_ip(ip_address):
    ip_addr_hex = []
    for block in ip_address.split("."):
        ip_addr_hex.append(format(int(block), "02x"))
    ip_addr_hex.reverse()
    return "0x" + "".join(ip_addr_hex)


def to_sin_port(port):
    port_hex = format(int(port), "04x")
    return "0x" + str(port_hex[2:4]) + str(port_hex[0:2])


def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))


def push_function_hash(function_name):
    edx = 0x00
    ror_count = 0
    for eax in function_name:
        edx = edx + ord(eax)
        if ror_count < len(function_name)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    return ("push " + hex(edx))


    
if __name__ == "__main__":
    print('[OpenProcessToken]\n', push_function_hash("OpenProcessToken"))
    print('[GetDefaultUserProfileDirectoryA]\n', push_function_hash("GetDefaultUserProfileDirectoryA"))
    print('[WinExec]\n', push_function_hash("WinExec"))