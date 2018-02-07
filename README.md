# For the blocklists, visit: [justdomains/blocklists](https://github.com/justdomains/blocklists)

-----

# justdomains/ci [![Build Status](https://travis-ci.org/justdomains/ci.svg?branch=master)](https://travis-ci.org/justdomains/ci)

Automated scripts to support converting filter lists (in various formats) to "domain-only" lists for use in DNS / domain-blocking tools like Pi-Hole.

# For normal users:
### Constantly-updated blocklists are [available here](https://github.com/justdomains/blocklists).
You do not need to run these scripts yourself if you just want the resulting blocklists. The link above has the automatically-updated output of this script for many common / popular lists.

If you have a blocklist you'd like added, [open a new issue here](https://github.com/justdomains/ci/issues).

# For advanced users:

If you'd like to run these scripts yourself, you can clone this git repository or download the following 3 files:
- [**convertlists.py**](#convertlistspy)
- [**lists.json**](#listsjson)
- buildrepo.py _(optional, used to build the list-hosting repo you see at: [justdomains/blocklists](https://github.com/justdomains/blocklists))_

### Requirements:
- Python 3.3+
- [requests](https://pypi.python.org/pypi/requests) 2.18+

## convertlists.py

Download and convert a series of lists (provided by [**`lists.json`**](#listsjson)) to a "domains-only" format.

This script outputs **only** the full-domain-blocking entries from the original lists, while attempting to filter any domains that conflict with an exception rule on the original list, thus creating output files that are useful in DNS / domain-blocking tools.

**Supported input list formats:** [Adblock Plus Filter](https://adblockplus.org/filters), HOSTS file

### Example Usage:
```sh
./convertlists.py lists.json converted/
```
(Will convert the lists specified by `lists.json`, and output files into the folder `converted/`)

## lists.json:
As input, **convertlists.py** requires the path to a **`lists.json`** file, which contains an array of dictionaries describing each list.

The **required** dictionary keys / values for each list are:

| key | value |
| -- | -- |
| **"name"** | the list name (string) |
| **"url"** | the URL from which the list will be downloaded (http://, https://), or a local file:// url (string) |
| **"format"** | the format of the list (string; possible values: **"adbp"**, **"hosts"**)

Optional dictionary keys / values for each list are:

| key | value |
| -- | -- |
| **_"license"_** | used to supply a license URL or description, if no license information can be extracted from the list itself (string) |
| **_"license-identifier"_** | a short license name / title (ex. "GPL3", "MIT") |
| **_"outputfile"_** | the base filename used for both the downloaded original and the converted output file (string) - important if multiple downloaded lists have the same filename |

### Example:

[View the **example `lists.json`** in this repo](lists.json).
