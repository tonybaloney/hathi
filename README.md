# Hathi

A SQL host scanner and dictionary attack tool. Comes with a script (`filter_pass.py`) to filter a series of password lists based on password strength.

```default
usage: hathi [-h] [--usernames USERNAMES] [--passwords PASSWORDS] [--results RESULTS] [--hostname HOSTNAME] [--verbose] [--mssql] [--postgres] [--multiple] host [host ...]

Port scan and dictionary attack PostgreSQL and MSSQL servers.

positional arguments:
  host                  host to scan

optional arguments:
  -h, --help            show this help message and exit
  --usernames USERNAMES
                        password list
  --passwords PASSWORDS
                        password list
  --results RESULTS     path to a results file
  --hostname HOSTNAME   an @hostname to append to the usernames
  --verbose             Enable verbose logging
  --mssql               Host is MSSQL
  --postgres            Host is Postgres
  --multiple            Seek multiple username/password pairs on a single host
```

Use a wordlist generator like [this one](https://github.com/zzztor/intelligence-wordlist-generator) or [this one](https://github.com/sc0tfree/mentalist) to create more effective password lists. 
