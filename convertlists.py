#!/usr/bin/env python3
#
# Requires: Python 3.3+
#
# Download and convert a series of lists (provided by `lists.json`) to a "domains-only" format.
#
# This script outputs **only** the full-domain-blocking entries from the original lists, while attempting to filter any domains that conflict with an exception rule on the original list, thus creating output files that are useful in DNS/domain-blocking tools.
# 
# Supported input list formats: [Adblock Plus Filter](https://adblockplus.org/filters), HOSTS file
#
# [lists.json]:
# As input, this script requires the path to a `lists.json` file, which contains an array of dictionaries describing each list.
#
# The **required** dictionary keys/values for each list are:
#    "name": the list name (string)
#    "url": the URL from which the list will be downloaded (http://, https://), or a local file:// url (string)
#    "format": the format of the list (string; possible values: "adbp", "hosts")
#
# Optional dictionary keys/values for each list are:
#    "license": used to supply a license URL or description, if no license information can be extracted from the list itself (string)
#    "license-identifier": a short license name / title (ex. "GPL3", "MIT")
#    "outputfile": the base filename used for both the downloaded original and the converted output file (string) - important if multiple downloaded lists have the same filename
#
# [Example Usage]:
#    ./convertlists.py lists.json converted/
# (Will convert the lists specified by `lists.json`, and output files into the folder converted/)
#
# [License]:
#     Copyright (c) 2018 justdomains contributors (https://github.com/justdomains)
#     MIT License (https://github.com/justdomains/ci/LICENSE)
#

import time
import json
import requests
from urllib.parse import urlparse
from datetime import timedelta
import re
import fnmatch
import os
import errno
import ipaddress
import argparse

def is_valid_hostname(hostname: str) -> bool:
    if len(hostname) > 255:
        return False
    hostname = hostname.rstrip(".")
    allowed = re.compile('^[a-z0-9]([a-z0-9\-\_]{0,61}[a-z0-9])?$',
                        re.IGNORECASE)
    labels = hostname.split(".")
    
    # the TLD must not be all-numeric
    if re.match(r"^[0-9]+$", labels[-1]):
        return False
    
    return all(allowed.match(x) for x in labels)


def _parse_headers_for_list_details(headerdict):

    output = dict()
    
    if "version" in headerdict:
        output["Version"] = headerdict["version"]

    if "last modified" in headerdict:
        output["Last Modified"] = headerdict["last modified"]
    elif "last updated" in headerdict:
        output["Last Modified"] = headerdict["last updated"]
    elif "last update" in headerdict:
        output["Last Modified"] = headerdict["last update"]
    elif "updated" in headerdict:
        output["Last Modified"] = headerdict["update"]
    elif "date" in headerdict:
        output["Last Modified"] = headerdict["date"]

    if "license" in headerdict:
        output["License"] = headerdict["license"]
    elif "licence" in headerdict:
        output["License"] = headerdict["licence"]

    if "title" in headerdict:
        output["Title"] = headerdict["title"]

    if "homepage" in headerdict:
        output["Homepage"] = headerdict["homepage"]
    
    return output


class AdbpExceptions:

    WILDCARD_LABELS_KEY = '!wildcardlabels' # type: str

    def _parse_exceptions(self, inputfile) -> None:
        self._exceptions = list()
        self._exceptions_domainsonly_tree = dict()
        for line in inputfile:
            if line.startswith('@@||'):
                # strip options
                exceptionrule = line[4:].rstrip('\n').split('$', 1)[0]

                # determine the format of the rule
                if exceptionrule.startswith('/'):
                    # TODO: Eventually support regex exception rules
                    print("\tWARNING: convertlists.py does not currently support regex exceptions, and so will ignore them (rule: '{}')".format(exceptionrule))
                    continue # Skip to next exception

                # wildcard rule
                # reduce the exception down to a domain (if a "^" is present)
                wildcard_domain = exceptionrule.split('^', 1)[0].rstrip(".")
                # since some rules do not use "^" but instead specify a literal separator (":", "?", "/"), split on those as well
                wildcard_domain = wildcard_domain.split(":", 1)[0].split("?", 1)[0].split("/", 1)[0]
                # split up the wildcard domain into labels and store in a tree
                wildcard_domain_labels = wildcard_domain.split(".")
                current_node = self._exceptions_domainsonly_tree
                for label in reversed(wildcard_domain_labels):
                    if label not in current_node:
                        current_node[label] = dict()
                        if "*" in label:
                            # Add the label to a special "wildcarded labels" list at this level
                            if AdbpExceptions.WILDCARD_LABELS_KEY not in current_node:
                                current_node[AdbpExceptions.WILDCARD_LABELS_KEY] = dict()
                            current_node[AdbpExceptions.WILDCARD_LABELS_KEY][label] = True
                    current_node = current_node[label]

            	# store each (raw) exception rule
                self._exceptions.append(exceptionrule)

    def __init__(self, inputfile) -> None:
        self._parse_exceptions(inputfile)

    def _domainlabels_exceptiontree_search(self, domain: str, current_node, matching_stack) -> bool:
        rightmost_domain_label = ""
        rightmost_domain_label_start = domain.rfind('.')
        if rightmost_domain_label_start == -1:
            # Only a single label left
            rightmost_domain_label = domain
        else:
            rightmost_domain_label = domain[rightmost_domain_label_start+1:]

        if rightmost_domain_label in current_node:
            # Exact match available - recurse (if needed)
            matching_stack.append(rightmost_domain_label)
            if rightmost_domain_label_start == -1:
                # print("\t\tFound exception match: {!s}".format(".".join(reversed(matching_stack))))
                return True
            elif self._domainlabels_exceptiontree_search(domain[:rightmost_domain_label_start], current_node[rightmost_domain_label], matching_stack):
                return True
            matching_stack.pop()

        if AdbpExceptions.WILDCARD_LABELS_KEY in current_node:
            # Now look for wildcard matches
            for wildcard_exception_label in current_node[AdbpExceptions.WILDCARD_LABELS_KEY]:
                if fnmatch.fnmatch(rightmost_domain_label, wildcard_exception_label):
                    # Wildcard match - recurse (if needed)
                    matching_stack.append(wildcard_exception_label)
                    if rightmost_domain_label_start == -1:
                        # print("\t\tFound exception match: {!s}".format(".".join(reversed(matching_stack))))
                        return True
                    elif self._domainlabels_exceptiontree_search(domain[:rightmost_domain_label_start], current_node[wildcard_exception_label], matching_stack):
                        return True
                    matching_stack.pop()

        return False

    def exception_affects_domain(self, domain: str) -> bool:
        return self._domainlabels_exceptiontree_search(domain.rstrip("."), self._exceptions_domainsonly_tree, list())


def _adbp_parse_headers_for_list_details(headerdict):
    return _parse_headers_for_list_details(headerdict)


# Convert Adblock Plus format list to a domains-only list
def convertlist_adbp(inputfile, adbpconfiguration, outputfile):

    lines_processed = 0 # type: int
    comment_lines = 0 # type: int
    empty_lines = 0 # type: int
    domain_rules = 0 # type: int
    domains_retained = 0 # type: int
    domains_excluded = 0 # type: int
    domains_unsupportedoptions = 0 # type: int

    header_parameters = dict()
    past_header = False # type: bool

    verbosity = adbpconfiguration['verbosity']

    # process exceptions
    exceptions = AdbpExceptions(inputfile) # type: AdbpExceptions
    
    inputfile.seek(0)
    for line in inputfile:
        lines_processed += 1

        if lines_processed == 1 and line.startswith("["):
            continue # Ignore first line if it starts with "["

        if line.startswith('!'):
            # Comment line
            comment_lines += 1

            if past_header:
                continue # Ignore all comments past header

            # When processing the header, extract parameters from comments
            split_header_line = line[1:].strip().split(": ", 1)
            if len(split_header_line) == 2:
                header_key = split_header_line[0].lower()
                if header_key in header_parameters:
                    if verbosity >= 2:
                        print("\tINFO: Duplicate header parameter for key '{}' found. Ignoring.".format(header_key))
                    continue
                header_parameters[header_key] = split_header_line[1]
            
        elif line.startswith('||'):
            # Rule begins with a domain - process
            past_header = True
            domain_rules += 1
            splitline = line[2:].rstrip('\n').split('$', 1) # Split the rule at any options
            
            # Process matching part of rule
            matchingparts = splitline[0].split('^', 1)
            if len(matchingparts) != 2:
                # A strict domain rule *must* contain a "^" to denote the end of the domain (or the rule actually matches a prefix)
                continue # Skip this rule
            
            if len(matchingparts[1]) > 0:
                # A rule that specifies anything after the domain cannot be included
                continue # Skip this rule
            
            if not is_valid_hostname(matchingparts[0]):
		# The rule does not simply specify a valid hostname (may specify a path, query parameters, etc)
                continue # Skip this rule
            
            domain = matchingparts[0] # type: str
            
            if len(splitline) > 1:
                # Process options
                options = splitline[1].split(',')
                hasOnlySupportedOptions = True
                for option in options:
                    if option not in adbpconfiguration['supportedoptions']:
                        hasOnlySupportedOptions = False
                        break
                if not hasOnlySupportedOptions:
                    domains_unsupportedoptions += 1
                    continue # Skip this rule
            
            # Check if any exceptions would impact this domain (or subdomains)
            if exceptions.exception_affects_domain(domain):
                if verbosity >= 3:
                    print("\tINFO: Ignoring block on domain '{}' because at least one exception matches the domain, a subdomain, or a potential path on that domain or subdomain".format(domain))
                domains_excluded += 1
                continue # Skip this rule

            # Output the domain
            outputfile.write(domain + '\n')
            domains_retained += 1

        else:
            past_header = True

            if len(line.strip()) == 0:
                empty_lines += 1

    headerinfo = dict()
    headerinfo = _adbp_parse_headers_for_list_details(header_parameters)
    processinginfo = list()
    processinginfo.append(("Total Lines Processed", lines_processed))
    processinginfo.append(("Comment Lines", comment_lines))
    processinginfo.append(("Empty Lines", empty_lines))
    processinginfo.append(("Non-Domain-only Rules Excluded", lines_processed - comment_lines - domains_retained - domains_excluded - domains_unsupportedoptions))
    processinginfo.append(("Domain-only Rules Excluded (unsupported options)", domains_unsupportedoptions))
    processinginfo.append(("Domain-only Rules Excluded (exception conflict)", domains_excluded))
    processinginfo.append(("Domain-only Rules Output", domains_retained))

    if verbosity >= 2:
        for line in processinginfo:
            print("\t{!s}: {!s}".format(line[0], line[1]))

    return {"Header": headerinfo, "Conversion": processinginfo, "Domains Output": domains_retained}


def is_hostfile_ignored_host(host: str) -> bool:
    # Ignore "localhost", "localhost6", or anything that starts with either
    if host.startswith("localhost"):
        return True

    # Ignore anything that ends in ".localdomain" or ".localdomain6"
    if host.endswith(".localdomain") or host.endswith(".localdomain6"):
        return True

    # Ignore "loopback"
    if "loopback" == host:
        return True

    # Ignore "local"
    if "local" == host:
        return True

    # Otherwise
    return False

def _hosts_parse_header_comments_for_list_details(headerdict):
    return _parse_headers_for_list_details(headerdict)

# Convert HOSTS format file to a domains-only list
def convertlist_hosts(inputfile, hostsconfiguration, outputfile):

    lines_processed = 0 # type: int
    comment_lines = 0 # type: int
    empty_lines = 0 # type: int
    invalid_lines = 0 # type: int
    nonloopback_lines = 0 # type: int
    ignored_localhosts = 0 # type: int
    invalid_hosts = 0 # type: int
    duplicate_hosts = 0 # type: int
    hosts = 0 # type: int

    unique_hosts = set()

    header_parameters = dict()
    past_header = False # type: bool

    verbosity = hostsconfiguration['verbosity']
    
    inputfile.seek(0)
    for line in inputfile:
        lines_processed += 1

        line = line.strip()

        if line.startswith('#'):
            # Comment line
            comment_lines += 1

            if past_header:
                continue # Ignore all comments past header

            # When processing the header, extract parameters from comments
            split_header_line = line[1:].strip().split(": ", 1)
            if len(split_header_line) == 2:
                header_key = split_header_line[0].lower()
                if header_key in header_parameters:
                    print("\tINFO: Duplicate header parameter for key '{!s}' found. Ignoring.".format(header_key))
                    continue
                header_parameters[header_key] = split_header_line[1]
        elif len(line) == 0:
            # Empty line
            empty_lines += 1
            continue

        else:
            past_header = True

            # Process line

            # Remove anything after first "#" character (i.e. any trailing comment)
            line = line.split('#', 1)[0]

            # Split line at whitespace
            line_components = line.split()

            if len(line_components) < 2:
                invalid_lines += 1
                continue # Ignore lines with fewer than 2 components

            # Verify that the first parameter is a valid IPv4 or IPv6 address
            valid_ip_address = False
            try:
                ip = ipaddress.ip_address(line_components[0])
                valid_ip_address = True
            except ValueError:
                pass

            if not valid_ip_address:
                invalid_lines += 1
                continue # Ignore lines without a valid IP address

            # Verify that the first parameter is a valid HOSTS file loopback IPv4 or IPv6 address
            if not ip.is_loopback and not line_components[0] == '0.0.0.0':
                if verbosity >= 3:
                    print("\tINFO: Ignoring line lacking valid 'blocking' IP address: '{!s}'".format(line))
                nonloopback_lines += 1
                continue # Ignore lines where the first parameter isn't a valid loopback IP address

            for host in line_components[1:]:
                # Verify the host isn't a loopback / localhost / ignored local host
                if is_hostfile_ignored_host(host):
                    if verbosity >= 3:
                        print("\tINFO: Ignoring 'local' host '{!s}' from line: '{!s}'".format(host, line))
                    ignored_localhosts += 1
                    continue # Skip

                # Verify host is a valid hostname
                if not is_valid_hostname(host):
                    if verbosity >= 3:
                        print("\tINFO: Ignoring invalid host '{!s}' from line: '{!s}'".format(host, line))
                    invalid_hosts += 1
                    continue # Skip invalid hostnames


                # Verify the host isn't a duplicate in this file
                if host in unique_hosts:
                    duplicate_hosts += 1
                    continue # Skip duplicate host

                # Output the host
                outputfile.write(host + '\n')
                unique_hosts.add(host)
                hosts += 1

    headerinfo = dict()
    headerinfo = _hosts_parse_header_comments_for_list_details(header_parameters)
    processinginfo = list()
    processinginfo.append(("Total Lines Processed", lines_processed))
    processinginfo.append(("Comment Lines", comment_lines))
    processinginfo.append(("Empty Lines", empty_lines))
    processinginfo.append(("Invalid Lines", invalid_lines))
    processinginfo.append(("Non-Loopback Lines (Ignored)", nonloopback_lines))
    processinginfo.append(("Local Hosts (Ignored)", ignored_localhosts))
    processinginfo.append(("Invalid Hosts (Ignored)", invalid_hosts))
    processinginfo.append(("Duplicate Hosts (Ignored)", duplicate_hosts))
    processinginfo.append(("Hosts Output", hosts))

    if verbosity >= 2:
        for line in processinginfo:
            print("\t{!s}: {!s}".format(line[0], line[1]))

    return {"Header": headerinfo, "Conversion": processinginfo, "Domains Output": hosts}

# Convert an input list, given a specific input format (and format configuration) to a domains-only output file
def convertlist(inputfile, form, formatconfiguration, outputfile):
    if form == 'adbp':
        return convertlist_adbp(inputfile, formatconfiguration, outputfile)
    elif form == 'hosts':
        return convertlist_hosts(inputfile, formatconfiguration, outputfile)
    else:
        # Currently unsupported format
        raise ValueError("Currently unsupported format: \'{!s}\'".format(form))

# Appends a string to a filename (prior to the file extension)
# For example, appendtofilename("file.txt", "-tmp") yields "file-tmp.txt"
def appendtofilename(filename: str, string_to_append: str) -> str:
    splitfilename = os.path.splitext(filename)
    return splitfilename[0] + string_to_append + splitfilename[1]

#######################
# Main

# Retrieve the input path and output path as arguments
parser = argparse.ArgumentParser()
parser.add_argument("listsjson", help="path to the input `lists.json` file, describing the lists the script should process")
parser.add_argument("outputpath", help="path to a desired output folder in which the converted lists will be saved, along with a `details.json` file describing details of the conversion process and output files")
parser.add_argument("-d", "--dlpath", default="originals/",
                    help="the path in which to save downloaded original list files (defaults to: originals/)")
parser.add_argument("-v", "--verbosity", action="count", default=0)
args = parser.parse_args()

# Configuration
converted_output_lists_locations = os.path.join(args.outputpath, "lists/") # type: str

# Ensure that the output directories exist
os.makedirs(os.path.dirname(args.dlpath), exist_ok=True)
os.makedirs(os.path.dirname(args.outputpath), exist_ok=True)
os.makedirs(os.path.dirname(converted_output_lists_locations), exist_ok=True)

# Configure request headers
#   Note: `request` 2.12.x and earlier clobber default headers, requiring the following method (see: https://stackoverflow.com/a/10606260)
#   Get a copy of the default headers that requests uses
request_headers = requests.utils.default_headers()
#   Update the User-Agent
#   (for Cloudflare's Browser Integrity Check: https://support.cloudflare.com/hc/en-us/articles/200170086-What-does-the-Browser-Integrity-Check-do-)
request_headers.update(
    {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
    }
)

print("Converting...")

# Load list configuration
unique_output_files = set()
lists_details = list()
with open(args.listsjson) as json_data:
    json_object = json.load(json_data)

    if not isinstance(json_object, list):
        raise ValueError("Root element of lists.json must be an array")

    if len(json_object) == 0:
        raise ValueError("Root element of lists.json does not contain any entries.")

    # For each list in the configuration JSON
    for filterlist in json_object:
        if 'name' not in filterlist:
            raise ValueError("Missing required 'name' key for list; (string)")
        if 'url' not in filterlist:
            raise ValueError("Missing required 'url' key for list; (string)")
        if 'format' not in filterlist:
            raise ValueError("Missing required 'format' key for list; (string) possible values: \"adbp\", \"hosts\"")

        parsedurl = urlparse(filterlist['url'])

        # Construct output filename
        outputfilename = '' # type: str
        try:
            outputfilename = filterlist['outputfile']
        except KeyError:
            outputfilename = os.path.basename(parsedurl.path)
            pass
        basefilename = outputfilename # type: str
        outputfilename = appendtofilename(basefilename, "-justdomains")

        if basefilename in unique_output_files:
            # More than one list is configured to use the same output filename
            # One or more of the entries in lists.json should have their 'outputfile' property set to distinct values to avoid this.
            raise ValueError("More than one list in lists.json is currently configured to use the same output filename '{!s}'. To fix this, modify the list dictionaries to specify distinct 'outputfile' filenames".format(basefilename))
        unique_output_files.add(basefilename)

        locallistfile = "" # type: str
        if parsedurl.scheme == "http" or parsedurl.scheme == "https":
	    # Download the list (to a local file)
            if args.verbosity >= 1:
                print("[{!s}]: Fetching list from: {!s} ...".format(filterlist['name'], filterlist['url']))
            locallistfile = os.path.join(args.dlpath, basefilename)
            start_time = time.monotonic()
            r = requests.get(filterlist['url'], stream=True, headers=request_headers)
            if r.status_code != 200:
                print('[{!s}]: ERROR: Unable to download "{!s}"; received HTTP status: {}; skipping'.format(filterlist['name'], filterlist['url'], r.status_code))
                continue
            with open(locallistfile, "wb") as f:
                for chunk in r.iter_content(chunk_size=8 * 1024):
                    if chunk: # Filter out keep-alive new chunks
                        f.write(chunk)
            end_time = time.monotonic()
            if args.verbosity >= 1:
                print("[{!s}]: Fetch completed ({} bytes, in {:.2f} seconds)".format(filterlist['name'], os.path.getsize(locallistfile), (end_time - start_time)))
        elif parsedurl.scheme == "file":
            # Simply use the local file path
            locallistfile = parsedurl.path
            if not os.path.exists(locallistfile):
                print('[{!s}]: ERROR: Input list file does not exist at path: "{!s}"; skipping'.format(filterlist['name'], filterlist['url']))
                continue
        else:
             # Unsupported scheme
             raise ValueError("Unsupported url format: '{!s}'; Expecting 'https://', 'http://', or 'file://' scheme.".format(filterlist['url']))

        # Determine the conversion format configuration
        formatconfiguration = {'verbosity': args.verbosity}
        if filterlist['format'] == 'adbp':
            # For Adblock Plus format filter lists, include domain-only entries with the solo option "third-party"
            formatconfiguration['supportedoptions'] = {'third-party': ''}

        # Convert the list
        if args.verbosity >= 1:
            print("[{!s}]: Processing: {!s} ...".format(filterlist['name'], locallistfile))
        start_time = time.monotonic()
        listdetails = dict()
        with open(os.path.join(converted_output_lists_locations, outputfilename), 'w') as f:
            with open(locallistfile, 'r') as inputfile:
            	listdetails = convertlist(inputfile, filterlist['format'], formatconfiguration, f)
        end_time = time.monotonic()
        if args.verbosity >= 1:
            print("[{!s}]: Processing completed ({:.2f} seconds)".format(filterlist['name'], (end_time - start_time)))

        # Aggregate the list and output details
        output_formats = dict()
        output_formats['Just Domains'] = outputfilename
        list_info = dict()
        list_info['Title'] = filterlist['name']
        list_info['Source'] = filterlist['url']
        if 'license' in filterlist:
            list_info['License'] = filterlist['license']
        if 'license-identifier' in filterlist:
            list_info['License Identifier'] = filterlist['license-identifier']
        list_info['Base Output Filename'] = appendtofilename(basefilename, "-{FORMAT}")
        list_info['Header'] = listdetails['Header']
        list_info['Conversion'] = listdetails['Conversion']
        list_info['Output Formats'] = output_formats
        list_info['Domains Output'] = listdetails['Domains Output']

        lists_details.append(list_info)

        if args.verbosity >= 1:
            print("[{!s}]: Converted list saved to: {!s}".format(filterlist['name'], os.path.join(converted_output_lists_locations, outputfilename)))


# Output the details.json file
with open(os.path.join(args.outputpath, 'details.json'), 'w') as outfile:
    json.dump(lists_details, outfile, indent=4)

print("Finished converting.")
if args.verbosity >= 1:
    print("Details saved in: {!s}".format(os.path.join(args.outputpath, 'details.json')))
