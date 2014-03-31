#!/usr/bin/env python3
#
# script that converts between
# openSSH 'known hosts' to what putty
# stores in the registry for its known hosts
#
#
# written by Mark Grandi, March 27, 2014
#



import binascii
import struct
import base64
import io
import sys
import argparse
import os, os.path
import collections
import re
import winreg
import socket
import math

# represents the data that would go inside the registry key for the putty known hosts
# example:
# keyName = rsa2@23:68.98.45.184
# exponent = 0x10001
# modulus: 0xaaaaa027...........
PuttyKnownhostEntry = collections.namedtuple("PuttyKnownhostEntry", ["keyName", "exponent", "modulus"])


def main(args):
    ''' figures out what function to call
    @param args - the argument parser Namespace object we got from parse_args()
    '''
    print(args)

    if args.convert_to_openssh:
        puttyToOpenSSH(args)


    else:
        openSSHToPutty(args)


def puttyToOpenSSH(args):
    ''' converts putty known hosts entries to openSSH ones
    @param args - the argument parser Namespace object we got from parse_args()
    '''


    # open the registry key that has the Known hosts
    puttyKey = None
    try:
        puttyKey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\SimonTatham\\PuTTY\\SshHostKeys")
    except OSError:
        raise Exception("could not open the registry key containing the putty known host entries, are there any in there?")

    # iterate over them, creating PuttyKnownhostEntry objects
    puttyEntries = []
    counter = 0
    while True:

        key = None
        value = None
        dataType = None
        try:
            key, value, dataType = winreg.EnumValue(puttyKey, counter)
        except OSError:
            # no more data
            break


        exp = value.split(",")[0]
        modulus = value.split(",")[1]
        puttyEntries.append(PuttyKnownhostEntry(key, exp, modulus))

        counter += 1


    # now go through each entry and convert it to a openssh line
    openSshLines = []
    for iterEntry in puttyEntries:

        # parse the key name, which has the hostname or ip, port, and algorithm
        # it looks like: 'rsa2@60101:mgrandi.no-ip.org'
        alg = iterEntry.keyName.split("@")[0]
        opensshAlg = ""
        if alg == "rsa2":
            opensshAlg = "ssh-rsa"
        elif alg == "dsa":
            opensshAlg = "ssh-dss"

        secondPart = iterEntry.keyName.split("@")[1]
        port = secondPart.split(":")[0] # putty always stores the port

        hostOrIp = secondPart.split(":")[1]
        hostName = hostOrIp

        # if the user wants to resolve ip addresses, do it
        # TODO: if we want ipv6 support we should somehow have an option to choose the 
        # ipv6 address if present from the result we get from getaddrinfo()
        if args.should_resolve:
            addrList = socket.getaddrinfo(hostOrIp, port)

            hostName = addrList[0][4][0]

        # now calculate the data that it stores
        resultBytes = io.BytesIO()

        resultBytes.write(struct.pack(">i", 7)) # write that there is a 7 byte algorithm identifier

        resultBytes.write(opensshAlg.encode("utf-8")) # write algorithm identifier

        expInt = int(iterEntry.exponent[2:], 16)

        # how many bytes does it take to store this exponent?
        numBytes = math.ceil(int(expInt).bit_length() / 8)

        # write length of exponent
        resultBytes.write(struct.pack(">i", numBytes))

        # write exponent
        resultBytes.write(struct.pack(">{}s".format(numBytes), int(expInt).to_bytes(numBytes, "big")))


        modulusData = binascii.unhexlify(iterEntry.modulus[2:])

        # here we have to 'add' a b'\x00' byte to the start of this, because i guess we are padding the modulus
        # to match the RSA key modulus, see my comment later on in this file)
        modulusData = b'\x00' + modulusData

        # write length of modulus
        resultBytes.write(struct.pack(">i", len(modulusData)))

        # write modulus
        resultBytes.write(modulusData)


        # base64 it
        result = base64.b64encode(resultBytes.getvalue())

        # now we have the openssh line
        # put it in our list
        # (like [68.98.45.184]:23 ssh-rsa AAAAB3.....)
        openSshLines.append("[{}]:{} {} {}".format(hostName, port, opensshAlg, result.decode("utf-8")))


    import pprint
    pprint.pprint(openSshLines)




def openSSHToPutty(args):
    ''' converts OpenSSH known hosts entries to putty ones
    @param args - the argument parser Namespace object we got from parse_args()
    '''

    # see if we can find the openssh known_hosts file
    # or if the user provided us with one
    knownHostsPath = os.path.expanduser("~/.ssh/known_hosts")
    if args.openssh_knownhosts_file:
        knownHostsPath = os.path.realpath(args.openssh_knownhosts_file)


    # known_host entries are like this:
    # [hostname,]ip-addr algorithm data
    # github.com,192.30.252.131 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7h.......

    # i tested this by having a list of the different formats a known_hosts entry can have
    #   matchList = 
    #       ['github.com,192.30.252.131 ssh-rsa AAAAB3NzaC1yc2EAAAAB', 
    #       '192.30.252.130 ssh-rsa AAAAB3NzaC1yc2E', 
    #       '[68.98.45.184]:23 ssh-rsa AAAAB3NzaC1yc2EAAAADAQ', 
    #       '[mgrandi.no-ip.org]:23,[68.98.45.184]:23 ssh-rsa AAAAB3Nz']
    #
    #   def test():
    #   for iterStr in matchList:
    #       print("running {}".format(iterStr))
    #       try:
    #           print(knownHostRegex.search(iterStr).groupdict())
    #       except AttributeError:
    #           print("nomatch")
    knownHostRegex = re.compile('''
        ^                                       # start of line
        \[?                                     # optional '['
        (?P<hostname>[\w.-]+(?=.*,))?           # (optional) Matches the hostname, only if a comma comes afterwards
        \]?                                     # optioanl ']'
        :?                                      # optional ':' (only there if a port is specified)
        ((?<=:)[0-9]*)?                         # optional port attached to the hostname, only matches if its preceeded by ':'
        ,?                                      # optional comma
        \[?                                     # optional '['
        (?P<ipaddr>[0-9a-fA-F.:]+)              # ip address, should match ipv4 and ipv6 addresses although not tested for ipv6...
        \]?                                     # optional ']'
        :?                                      # optional ':'
        (?P<port>[0-9]+)?                       # port
        \s                                      # space
        (?P<algorithm>[a-z-]+)                  # algorithm name
        \s                                      # space
        (?P<data>[a-zA-Z+/0-9=]+)               # the data (modulo, exponent, etc), matches the standard base64 alphabet
        $                                       # end of line
        ''', re.VERBOSE | re.MULTILINE | re.UNICODE)

    # make sure file exists
    if not os.path.isfile(knownHostsPath):
        raise Exception("Unable to find known_hosts file, {} was not found!".format(knownHostsPath))

    knownHostFileData = None
    with open(knownHostsPath, "r", encoding="utf-8") as f:
        knownHostFileData = f.read()

    # go through every entry
    for iterMatch in knownHostRegex.finditer(knownHostFileData):

        iterMatchResult = opensshMatchToPuttyKnownhost(iterMatch)
        print("Key: {}\nValue: {},{}".format(iterMatchResult.keyName, iterMatchResult.exponent, iterMatchResult.modulus))
    

def opensshMatchToPuttyKnownhost(matchObj):
    '''takes in a re.Match object and converts the data inside to 
    a putty knownhost entry (that can be put inside regedit)

    @param matchObj - a re.Match object that we got from parsing the openssh known_hosts file
    @return a PuttyKnownhostEntry
    '''

    matchDict = matchObj.groupdict()

    
    resultStr = ""


    opensshBytes = io.BytesIO(base64.b64decode(matchDict["data"]))


    # number of bytes to read to get the algorithm identifier
    algIdentifierLen = struct.unpack(">i", opensshBytes.read(4))[0]

    # convert the algorithm identifier to how putty understands it
    opensshType = opensshBytes.read(algIdentifierLen).decode("utf-8")
    puttyKeyType = ""
    if opensshType == "ssh-rsa":
        puttyKeyType = "rsa2"
    elif opensshType == "ssh-dss":
        puttyKeyType = "dsa"
    else:
        raise Exception("Unknown algorithm identifier! ({})".format(opensshType))

    port = 22
    if matchDict["port"]:
       port = matchDict["port"] 

    # figure out keyname (for whats stored in the registry)
    keyName = ""
    if not matchDict["hostname"]:

        keyName = "{}@{}:{}".format(matchDict["algorithm"], port, matchDict["ipaddr"])
        
    else:
        # if no hostname, use the ip address
        keyName = "{}@{}:{}".format(matchDict["algorithm"], port, matchDict["hostname"])


    # read in the length of the exponent
    exponentLength = struct.unpack(">i", opensshBytes.read(4))[0]
    print("\texponent length is {}".format(exponentLength))

    # read in exponent
    exponent = int.from_bytes(opensshBytes.read(exponentLength), "big")
    print("\texponent  is {}".format(exponent))


    # read in length of modulus
    modLength = struct.unpack(">i", opensshBytes.read(4))[0]
    print("\tmodulus length is {}".format(modLength))

    # read in modulus
    modulus = opensshBytes.read(modLength)

    # ******************
    # NOTE NOTE NOTE:
    # *****************
    #
    # now we are ready to store it as a putty key
    # apparently we get rid of the leading 0...
    # because it needs to be padded to the length of the RSA key modulus
    #
    # from the putty docs:
    #
    # 4.25.7 `Requires padding on SSH-2 RSA signatures'
    #
    #        Versions below 3.3 of OpenSSH require SSH-2 RSA signatures to be
    #        padded with zero bytes to the same length as the RSA key modulus.
    #        The SSH-2 specification says that an unpadded signature MUST be
    #        accepted, so this is a bug. A typical symptom of this problem is
    #        that PuTTY mysteriously fails RSA authentication once in every few
    #        hundred attempts, and falls back to passwords.
    #
    #        If this bug is detected, PuTTY will pad its signatures in the way
    #        OpenSSH expects. If this bug is enabled when talking to a correct
    #        server, it is likely that no damage will be done, since correct
    #        servers usually still accept padded signatures because they're used
    #        to talking to OpenSSH.
    #
    #        This is an SSH-2-specific bug.
    #
    #
    # so i guess we just have to remove the leading 0, as i attempted this with a few and it doesn't work
    # unless the leading 0 is removed (tried github.com and launchpad.net)
    #

    if modulus[0:1] == b'\x00':
        # remove leading 0
        return PuttyKnownhostEntry(keyName, hex(exponent), "0x" + binascii.hexlify(modulus[1:]).decode("utf-8"))
    else:
        return PuttyKnownhostEntry(keyName, hex(exponent), "0x" + binascii.hexlify(modulus).decode("utf-8"))
 
    

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Program that converts between OpenSSH known hosts " + 
        "entries to PuTTY known hosts entries and vice versa", epilog="Copyright March 27, 2014 Mark Grandi")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--convert-to-putty", action="store_true")
    group.add_argument("--convert-to-openssh", action="store_true")

    parser.add_argument("--openssh-knownhosts-file", help="Specify a manual path to the openSSH " +
        "known_hosts file, in case we can't find it automatically")
    parser.add_argument("--should-resolve", action="store_true",
        help="Whether or not to resolve ip addresses and store that rather then the 'text' hostname")

    main(parser.parse_args())
