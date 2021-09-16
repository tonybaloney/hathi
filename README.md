# Hathi

[![PyPI version](https://badge.fury.io/py/hathi.svg)](https://badge.fury.io/py/hathi)

A SQL host scanner and dictionary attack tool. Comes with a script (`filter_pass.py`) to filter a series of password lists based on password strength.

## Installation

Install using PyPI to install the Postgres driver

```console
pip install hathi
```

For the optional MSSQL support, install

```console
pip install "hathi[mssql]"
```

## Usage

```default
usage: hathi [-h] [--usernames USERNAMES] [--passwords PASSWORDS] [--hostname HOSTNAME] [--json] [--mssql] [--postgres] [--multiple] host [host ...]

Port scan and dictionary attack PostgreSQL and MSSQL servers.

positional arguments:
  host                  host to scan

optional arguments:
  -h, --help            show this help message and exit
  --usernames USERNAMES
                        password list
  --passwords PASSWORDS
                        password list
  --hostname HOSTNAME   an @hostname to append to the usernames
  --json                Output in JSON
  --mssql               Force scanning hosts as MSSQL
  --postgres            Force scanning hosts as Postgres
  --multiple            Seek multiple username/password pairs on a single host
```

Use a wordlist generator like [this one](https://github.com/zzztor/intelligence-wordlist-generator) or [this one](https://github.com/sc0tfree/mentalist) to create more effective password lists.
