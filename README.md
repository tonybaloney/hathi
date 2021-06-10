# Hathi

A postgres host scanner and dictionary attack tool.

You'll need to supply your own dictionary (`username:password`) from SecLists. An example has been included for illustration purposes.

```default
usage: hathi.py [-h] [--dictionary DICTIONARY] [--results RESULTS] host [host ...]

Port scan and dictionary attack postgresql servers.

positional arguments:
  host                  host to connect to

optional arguments:
  -h, --help            show this help message and exit
  --dictionary DICTIONARY
                        dictionary list
  --results RESULTS     path to a results file
```