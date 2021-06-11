# Hathi

A postgres host scanner and dictionary attack tool. Comes with a script (`filter_pass.py`) to filter a series of password lists based on password strength.

```default
usage: hathi.py [-h] [--usernames USERNAMES] [--passwords PASSWORDS] [--results RESULTS] [--hostname HOSTNAME] [--verbose] host [host ...]

Port scan and dictionary attack postgresql servers.

positional arguments:
  host                  host to connect to

optional arguments:
  -h, --help            show this help message and exit
  --usernames USERNAMES
                        password list
  --passwords PASSWORDS
                        password list
  --results RESULTS     path to a results file
  --hostname HOSTNAME   an @hostname to append to the usernames
  --verbose
```
