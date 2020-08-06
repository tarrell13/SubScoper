#!/usr/bin/env python3
"""SubDomain Scoper

Usage:
  sub_scoper.py -s SUBDOMAIN_LIST -i IP_LIST [ --sort ORDER_TYPE ]
  sub_scoper.py --reorder OUTPUT_FILE
  sub_scoper.py (-h | --help)
  sub_scoper.py --version

Options:
  -i IP_LIST --input IP_LIST                File with IP addresses to validate against
  -s SUBDOMAIN_LIST --sub SUBDOMAIN_LIST    File containing SubDomains to check
  --reorder OUTPUT_FILE                     Reverses the sorting order of the output file
  --sort ORDER_TYPE                         Sort by 'domain' or 'address' DEFAULT is domain
  -h --help     Show this screen.
  --version     Show version.

  # FINISH THIS FLETCH!!! This would be helpful! Tomorrow it is!

"""
import dns.resolver
import ipaddress
import docopt
import json
import sys
import re


class Address(object):
    """ Each IP Address Instance Fields """
    def __init__(self, address):
        self.address = address
        self.domain_names = []
        self.validated = False


class SubDomain(object):
    """ Each SubDomain will become a Domain Object """
    def __init__(self, name):
        self.name = name
        self.resolved_addresses = []
        self.validated_addresses = []

IP_LIST = []
SUBDOMAIN_LIST = []


def load_data(data):
    """ Loads Data """

    data = json.loads(data)
    if data["Order"] == "domain":
        load_domain_key(data)
    elif data["Order"] == "ip":
        load_address_key(data)


def load_domain_key(data):
    """ Loads Data if Domain is Key """
    global SUBDOMAIN_LIST

    for sub, addresses in data["InScope"].items():
        temp = SubDomain(sub)
        for address in addresses:
            temp.validated_addresses.append(address)
        SUBDOMAIN_LIST.append(temp)

    write_output(add_domains_to_address(), order="ip")


def load_address_key(data):
    """ Loads Data if Address is Key """
    global SUBDOMAIN_LIST

    temp = {}

    ''' Add data to working structure '''
    for address, subs in data["InScope"].items():
        for sub in subs:
            if sub not in temp:
                temp[sub] = []
            temp[sub].append(address)

    ''' Create the instances '''
    for sub, addresses in temp.items():
        temp = SubDomain(sub)
        for address in addresses:
            temp.validated_addresses.append(address)
        SUBDOMAIN_LIST.append(temp)

    write_output(add_address_to_domain(), order="domain")


def add_address_to_domain():
    """ Adds the address to domain """
    temp = {}

    for sub in SUBDOMAIN_LIST:
        if sub.name not in temp:
            temp[sub.name] = []

        for address in sub.validated_addresses:
            if address not in temp[sub.name]:
                temp[sub.name].append(address)

    return temp


def add_domains_to_address():
    """ Adds the domain to the address """
    temp = {}

    for sub in SUBDOMAIN_LIST:
        for address in sub.validated_addresses:
            if address not in temp:
                temp[address] = []
            temp[address].append(sub.name)

    return temp


def write_output(data, order=None):
    """ Saves the output to a file """
    output = {"Order": None, "InScope": {}, "OutScope": {}}

    if order == "domain":
        for sub in SUBDOMAIN_LIST:
            if sub.name not in output["InScope"] and sub.validated_addresses:
                output["InScope"][sub.name] = []
                output["InScope"][sub.name] = sub.validated_addresses
        output["Order"] = "domain"
        filename = "domain_order_validation.json"

    elif order == "ip":
        for ip, domains in data.items():
            if ip not in output["InScope"]:
                output["InScope"][ip] = []
            for domain in domains:
                output["InScope"][ip].append(domain)
        output["Order"] = "ip"
        filename = "address_order_validation.json"

    with open(filename, "w") as handle:
        handle.write(json.dumps(output))

    sys.exit()


def validate_scope():
    """ Uses the SubDomain List to validate If IP exists within InScope File """
    global SUBDOMAIN_LIST

    for sub in SUBDOMAIN_LIST:
        for address in sub.resolved_addresses:
            if address in IP_LIST:
                sub.validated_addresses.append(address)


def retrieve_domain_address():
    """ Performs DNS lookup on each domain """
    global SUBDOMAIN_LIST

    resolver = dns.resolver.Resolver()
    copy_list = []

    for sub in SUBDOMAIN_LIST:
        copy_list.append(sub)

    for i in range(len(copy_list)):
        try:
            answers = resolver.resolve("%s" % copy_list[i].name, "A")
            for response in answers:
                copy_list[i].resolved_addresses.append(response.to_text())
        except dns.resolver.NoAnswer:
            SUBDOMAIN_LIST.pop(i)
            continue
        except dns.resolver.NXDOMAIN:
            SUBDOMAIN_LIST.pop(i)
            continue


def generate_sub_domain_list(input_file):
    """ Generates SubDomain Dictionary using input file """
    global SUBDOMAIN_LIST

    for line in input_file:
        line = line.rstrip()
        if line not in SUBDOMAIN_LIST:
            SUBDOMAIN_LIST.append(SubDomain(line))


def generate_ip_list(input_file):
    """ Generates IP List array using input file """
    global IP_LIST

    for line in input_file:
        line = line.rstrip()
        if re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", line):
            network = ipaddress.ip_network(line)
            for host in network.hosts():
                IP_LIST.append(Address(host.__str__()))
        elif re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
            IP_LIST.append(Address(line))


def main():

    args = docopt.docopt(__doc__, version='v1.0')

    if args["--reorder"]:
        load_data(open(args["--reorder"], "r").read())

    if not args["--input"]:
        print("[*] Specify IP Input File")

    if not args["--sub"]:
        print("[*] Specify SubDomain List")

    ip_input = open(args["--input"], "r").readlines()
    sub_input = open(args["--sub"], "r").readlines()

    generate_ip_list(ip_input)
    generate_sub_domain_list(sub_input)
    retrieve_domain_address()
    validate_scope()
    write_output()
    sys.exit()


if __name__ == "__main__":
    main()