#!/usr/bin/env python3
#
# Requires: Python 3
#
# This script takes as input the folder produced by `convertlist.py`
# and builds the "list hosting" repo in the specified output path.
#
# [Example usage of both scripts]:
#    ./convertlists.py lists.json converted/
#    ./buildrepo.py converted/ repo/ --downloadbaseurl https://raw.githubusercontent.com/justdomains/blocklists/master/
#
# Will output a list-hosting repo to `repo/` with proper links and content for pushing to the `master` branch of:
# https://github.com/justdomains/blocklists
# 
# [License]:
#     Copyright (c) 2018 justdomains contributors (https://github.com/justdomains)
#     MIT License (https://github.com/justdomains/ci/LICENSE)
#

import time
from datetime import datetime
import json
import os
import re
import hashlib
import subprocess
from urllib.parse import urlparse
import argparse

# Does a string appear to represent a URL?
def should_linkify(text: str) -> bool:
	r = urlparse(text)
	if r.scheme == "http" or r.scheme == "https":
		return True
	return False

def construct_github_anchor_link(text: str) -> str:
	# Lowercase the string
	anchor_link = text.lower()
	# Remove anything that is not a letter, number, space, or hyphen
	anchor_link = re.sub(r'[^\s\w\-]+', '', anchor_link, flags=re.UNICODE)
	anchor_link = re.sub(r'[_]+', '', anchor_link, flags=re.UNICODE) # Remove underscores (since \w includes underscores)
	# Change any space to a hyphen
	anchor_link = re.sub(r'\s', '-', anchor_link, flags=re.UNICODE)
	# NOTE: This does *not* handle non-unique anchors (i.e. by appending a "-" and a number)
	return anchor_link

def construct_download_link(dl_base_url: str, path_in_repo: str) -> str:
	if dl_base_url.strip().endswith("/"):
		return "{}{}".format(dl_base_url, path_in_repo)
	else:
		return "{}/{}".format(dl_base_url, path_in_repo) 

# Extract the license description / URL from the list data, and return it + the source
def get_license_info(filterlist):
	if 'License' in filterlist['Header'] and len(filterlist['Header']['License']) > 0:
		# Use the License information extracted from the list file itself
		return (filterlist['Header']['License'], 'List Header')
	elif 'License' in filterlist and len(filterlist['License']) > 0:
		# Use the License information provided to convertlists.py (via lists.json)
		return (filterlist['License'], 'Input')
	else:
		return ("", "No License Information")

# Construct the README.md file
def construct_readme_file(lists_info_array, downloadbaseurl: str, verbosity: int):
	lists_details = list()
	lists_details.append("# DOMAIN-ONLY Filter Lists")
	lists_details.append("**Last Updated:** {}".format((str(datetime.now())).split('.')[0]))
	lists_details.append("")
	lists_details.append("- [Details](#details)")
	lists_details.append("- [Usage](#usage)")
	lists_details.append("  - [Using with Pi-Hole](#using-with-pi-hole)")
	lists_details.append("  - [Using with other tools](#using-with-other-tools)")
	lists_details.append("- [The Lists](#the-lists)")
	for filterlist in lists_info_array:
		if verbosity >= 2:
			print("\tAdding List: \"{!s}\"".format(filterlist['Title']))
		lists_details.append("  - [{}](#{}) (Domains-only)".format(filterlist['Title'], construct_github_anchor_link(filterlist['Title'] + " (Domains-only)")))
	lists_details.append("- [License](#license)")
	lists_details.append("- [Reporting Conversion Issues](#reporting-conversion-issues)")
	lists_details.append("")
	lists_details.append("&nbsp;")
	lists_details.append("")
	lists_details.append("# Details:")
	lists_details.append("These are \"DOMAIN-ONLY\" **converted** versions of various popular original filter / blocking lists.")
	lists_details.append("They have been modified from their original versions by scripts at: https://github.com/justdomains/ci")
	lists_details.append("")
	lists_details.append("The scripts output **only** the full-domain-blocking entries from the original lists, while attempting to filter any domains that conflict with an exception rule on the original list.")
	lists_details.append("")
	lists_details.append("**Because these are automated, converted _subsets_ of the original lists, please do not report omissions from these converted files to the list originator.**")
	lists_details.append("")
	lists_details.append("&nbsp;")
	lists_details.append("")
	lists_details.append("# Usage:")
	lists_details.append("These converted files can be used with various DNS and domain-blocking tools:")
	lists_details.append("")
	lists_details.append("## Using with [Pi-Hole](https://pi-hole.net/):")
	lists_details.append("1. Copy the link to the Pi-Hole format for the desired list (from the appropriate table below).")
	lists_details.append("2. [Add the URL to your Pi-Hole's block lists (**Settings** > **Pi-Hole's Block Lists**).](https://github.com/pi-hole/pi-hole/wiki/Customising-Sources-for-Ad-Lists)")
	lists_details.append("")
	lists_details.append("## Using with other tools:")
	lists_details.append("The converted lists are provided in a \"Raw Domain List\" format that contains only domains, one per line. Many other tools / scripts can ingest this format to add them to your blocklist.")
	lists_details.append("")
	lists_details.append("&nbsp;")
	lists_details.append("")
	lists_details.append("# The Lists:")
	lists_details.append("")
	lists_details.append("| Converted List | Domains | Domain List Link | Last Updated | License |")
	lists_details.append(":- | - | :-: | - | - |")
	for filterlist in lists_info_array:
		raw_download_link = construct_download_link(downloadbaseurl, os.path.join("lists/", filterlist['Output Formats']['Just Domains']))
		last_updated = ""
		if 'Last Modified' in filterlist['Header']:
			last_updated = filterlist['Header']['Last Modified']

		license_info, license_source = get_license_info(filterlist)
		license_link = ""
		if 'License Identifier' in filterlist:
			if should_linkify(license_info):
				license_link = "[{}]({})".format(filterlist['License Identifier'], license_info)
			else:
				license_link = filterlist['License Identifier']
		elif len(license_info) > 0:
			if should_linkify(license_info):
				license_link = "[(link)]({})".format(license_info)
			else:
				license_link = license_info
		else:
			license_link = "(see source)"
		lists_details.append("| [{}](#{}) | {} | [Download]({}) | {} | {} |".format(filterlist['Title'], construct_github_anchor_link(filterlist['Title'] + " (Domains-only)"), filterlist['Domains Output'], raw_download_link, last_updated, license_link))
	lists_details.append("")
	lists_details.append("&nbsp;")
	lists_details.append("")
	for filterlist in lists_info_array:
		lists_details.append("## {} (Domains-only)".format(filterlist['Title']))
		# Output Formats Table
		lists_details.append("| Format | Raw Download Link |")
		lists_details.append("| --- | --- |")
		raw_download_link = construct_download_link(downloadbaseurl, os.path.join("lists/", filterlist['Output Formats']['Just Domains']))
		lists_details.append("| Raw Domain List | [{}]({}) |".format(filterlist['Output Formats']['Just Domains'], raw_download_link))
		lists_details.append("| Pi-Hole | [{}]({}) |".format(filterlist['Output Formats']['Just Domains'], raw_download_link))
		lists_details.append("")
		# Output Source List Information
		lists_details.append("**Source:** [{}]({})".format(filterlist['Source'], filterlist['Source']))
		header_output_list = ('Title', 'Version', 'Last Modified', 'Homepage')
		for key in header_output_list:
			if key in filterlist['Header']:
				if should_linkify(filterlist['Header'][key]):
					lists_details.append("- {}: [{}]({})".format(key, filterlist['Header'][key], filterlist['Header'][key]))
				else:
					lists_details.append("- {}: {}".format(key, filterlist['Header'][key]))
		lists_details.append("")
		# Output Conversion Details
		lists_details.append("**Conversion Details:**")
		lists_details.append("```")
		for conversion_output_tuple in filterlist['Conversion']:
			if len(conversion_output_tuple) != 2:
				if verbosity >= 1:
					print("\tERROR: Failed to output Conversion tuple because it does not have 2 items: {!s}".format(conversion_output_tuple))
				continue # Skip, currently unsupported
			lists_details.append("{}: {}".format(conversion_output_tuple[0], conversion_output_tuple[1]))
		lists_details.append("```")
		lists_details.append("")
		lists_details.append("&nbsp;")
		lists_details.append("")

	lists_details.append("# License:")
	lists_details.append("Each converted / modified list file is licensed under the same license as the original list.")
	lists_details.append("For more details, see the [LICENSE](LICENSE) file.")
	lists_details.append("")
	lists_details.append("&nbsp;")
	lists_details.append("")
	lists_details.append("# Reporting Conversion Issues:")
	lists_details.append("If you find an issue in the output of the conversion process (i.e. comparing to the original upstream list), please report it over on: https://github.com/justdomains/ci/issues")
	lists_details.append("")
	lists_details.append("**NOTE: We do not manage the upstream lists themselves, and will not be able to add any new blocks to the lists.**")
	lists_details.append("")
	lists_details.append("<sup>These files are provided \"AS IS\", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, arising from, out of or in connection with the files or the use of the files.</sup>")
	lists_details.append("")
	lists_details.append("<sub>Any and all trademarks are the property of their respective owners.</sub>")
	lists_details.append("")

	return lists_details


# Construct the LICENSE file
def construct_license_file(lists_info_array, verbosity: int):
	lists_licenses = list()
	lists_licenses.append("All converted / modified list files are licensed under the same license as the original list.")
	lists_licenses.append("")
	for filterlist in lists_info_array:
		license_info, license_source = get_license_info(filterlist)
		if len(license_info) > 0:
			lists_licenses.append("[{}]".format(filterlist['Base Output Filename']))
			lists_licenses.append("\tLicense: {}".format(license_info))
			if verbosity >= 2:
				print("\tAdding License for List \"{!s}\": \"{!s}\"; source='{!s}'".format(filterlist['Title'], license_info, license_source))
		elif verbosity >= 1:
			print("\tWARNING: No License Information Available for List: \"{!s}\"; skipping".format(filterlist['Title']))

	return lists_licenses


#######################
# Main

# Retrieve the input path and output path as arguments
parser = argparse.ArgumentParser()
parser.add_argument("inputpath", help="path to the output folder produced by convertlist.py")
parser.add_argument("outputpath", help="path to a desired output folder in which the list hosting repo's files will be built")
parser.add_argument("-dlurl", "--downloadbaseurl", required=True, help="the base public URL at which the contents of the repo/ folder will be accessible (once separately uploaded) - this is used for properly forming README list download links")
parser.add_argument("-v", "--verbosity", action="count", default=0)
args = parser.parse_args()

input_lists_path = os.path.join(args.inputpath, "lists/") # type: str

# Ensure that the output directory exists
os.makedirs(os.path.dirname(args.outputpath), exist_ok=True)

# rsync the lists folder
if args.verbosity >= 1:
	print("Syncing: {!s} -> {!s}".format(input_lists_path, os.path.join(args.outputpath, "lists/")))
rsync_call_array = ["rsync", "-avh", input_lists_path, os.path.join(args.outputpath, "lists/"), "--delete"]
if args.verbosity >= 2:
	print("\t{!s}".format(" ".join(rsync_call_array)))
rsync_output = subprocess.check_output(rsync_call_array, universal_newlines=True)
if args.verbosity >= 2:
	for line in rsync_output.split('\n'):
		if len(line.strip()) > 0:
			print("\t" + line)

# process the converted details.json into README and LICENSE files
with open(os.path.join(args.inputpath, 'details.json')) as json_data:
	json_object = json.load(json_data)
	if args.verbosity >= 1:
		print("Building: {!s}".format("README.md"))
	readme_lines = construct_readme_file(json_object, args.downloadbaseurl, args.verbosity)
	if args.verbosity >= 1:
		print("Building: {!s}".format("LICENSE"))
	license_lines = construct_license_file(json_object, args.verbosity)

	# Output README.md file
	if args.verbosity >= 1:
		print("Writing: {!s}".format(os.path.join(args.outputpath, "README.md")))
	with open(os.path.join(args.outputpath, 'README.md'), 'w') as f:
		f.write('\n'.join(readme_lines))

	# Output LICENSE file
	if args.verbosity >= 1:
		print("Writing: {!s}".format(os.path.join(args.outputpath, "LICENSE")))
	with open(os.path.join(args.outputpath, 'LICENSES'), 'w') as f:
		f.write('\n'.join(license_lines))

print("Finished building repo in: {!s}".format(args.outputpath))

