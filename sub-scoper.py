#!/usr/bin/env python3
"""SubDomain Scoper

Usage:
  sub_scoper.py -s SUBDOMAIN_LIST -i IP_LIST [ --sort ORDER_TYPE ]
  sub_scoper.py --reorder OUTPUT_FILE
  sub_scoper.py --domains-only OUTPUT_FILE
  sub_scoper.py (-h | --help)
  sub_scoper.py --version

Options:
  -i IP_LIST --input IP_LIST                File with IP addresses to validate against
  -s SUBDOMAIN_LIST --sub SUBDOMAIN_LIST    File containing SubDomains to check
  --domains-only OUTPUT_FILE                Outputs all the domains that were validated
  --reorder OUTPUT_FILE                     Reverses the sorting order of the output file
  --sort ORDER_TYPE                         Sort by 'domain' or 'address' DEFAULT is domain
  -h --help     Show this screen.
  --version     Show version.

"""
from progress.bar import FillingCirclesBar
import dns.resolver
import ipaddress
import docopt
import json
import sys
import re
import os


class SubDomain(object):
    """ Each SubDomain will become a Domain Object """
    def __init__(self, name):
        self.name = name
        self.resolved_addresses = []
        self.validated_addresses = []

IP_LIST = []
SUBDOMAIN_LIST = []
path = (os.path.dirname(os.path.realpath(__file__)))
order = "domain"


def load_data(data, domain_only=False):
    """ Loads Data """

    data = json.loads(data)
    if data["Order"] == "domain":
        load_domain_key(data, domain_only=domain_only)
    elif data["Order"] == "address":
        load_address_key(data, domain_only=domain_only)


def load_domain_key(data, domain_only=False):
    """ Loads Data if Domain is Key """
    global SUBDOMAIN_LIST

    for sub, addresses in data["InScope"].items():
        temp = SubDomain(sub)
        for address in addresses:
            temp.validated_addresses.append(address)
        SUBDOMAIN_LIST.append(temp)

    if domain_only:
        output_domains(add_domains_to_address())
    else:
        write_output(add_domains_to_address(), order="address")


def output_domains(data):
    """ Outputs only domains """
    for sub in SUBDOMAIN_LIST:
        print(sub.name)


def load_address_key(data, domain_only=False):
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

    if domain_only:
        output_domains(add_address_to_domain())
    else:
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


def write_output(data=None, order=None):
    """ Saves the output to a file """
    output = {"Order": None, "InScope": {}, "OutScope": {}}

    if order == "domain":
        for sub in SUBDOMAIN_LIST:
            if sub.name not in output["InScope"] and sub.validated_addresses:
                output["InScope"][sub.name] = []
                output["InScope"][sub.name] = sub.validated_addresses
        output["Order"] = "domain"
        filename = "domain_order_validation.json"

    elif order == "address":
        for ip, domains in data.items():
            if ip not in output["InScope"]:
                output["InScope"][ip] = []
            for domain in domains:
                output["InScope"][ip].append(domain)
        output["Order"] = "address"
        filename = "address_order_validation.json"

    if not os.path.isdir(path + "/output"):
        os.makedirs(path + "/output")

    with open(path + "/output/%s" % filename, "w") as handle:
        handle.write(json.dumps(output, indent=4))

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
    pop_list = []

    bar = FillingCirclesBar('[*] Resolving Domains', max=len(SUBDOMAIN_LIST))

    for i in range(len(SUBDOMAIN_LIST)):
        try:
            answers = resolver.resolve("%s" % SUBDOMAIN_LIST[i].name, "A")
            for response in answers:
                SUBDOMAIN_LIST[i].resolved_addresses.append(response.to_text())
        except dns.resolver.NoAnswer:
            pop_list.append(SUBDOMAIN_LIST[i])
        except dns.resolver.NXDOMAIN:
            pop_list.append(SUBDOMAIN_LIST[i])
        bar.next()
    bar.finish()

    SUBDOMAIN_LIST = adjust_list(pop_list)


def adjust_list(remove_list):
    """ Removes items from main list """
    temp = []

    for sub in SUBDOMAIN_LIST:
        if sub not in remove_list:
            temp.append(sub)

    return temp


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
                IP_LIST.append(host.__str__())
        elif re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", line):
            IP_LIST.append(line)


def main():

    args = docopt.docopt(__doc__, version='v1.2')

    if args["--reorder"]:
        load_data(open(args["--reorder"], "r").read())

    if args["--domains-only"]:
        load_data(open(args["--domains-only"], "r").read(), domain_only=True)
        sys.exit()

    if not args["--input"]:
        print("[*] Specify IP Input File")
        sys.exit()

    if not args["--sub"]:
        print("[*] Specify SubDomain List")
        sys.exit()

    ''' Generate Instances '''
    generate_ip_list(open(args["--input"], "r").readlines())
    generate_sub_domain_list(open(args["--sub"], "r").readlines())

    ''' Perform Resolution and Validation '''
    retrieve_domain_address()
    validate_scope()

    if args["--sort"]:
        if args["--sort"] == "domain":
            write_output(add_address_to_domain(), order="domain")
        elif args["--sort"] == "address":
            write_output(add_domains_to_address(), order="address")
    else:
        write_output(add_address_to_domain(), order="domain")


if __name__ == "__main__":
    main()
