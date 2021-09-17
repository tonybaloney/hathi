"""
Requirements:
 > pip install -r requirements.txt


Usage: hathi [-h] [--usernames USERNAMES] [--passwords PASSWORDS] [--results RESULTS] [--hostname HOSTNAME] [--verbose] host [host ...]

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
"""

import argparse
from hathi.mysql import MysqlScanner
from hathi.scanner import Scanner
from hathi.mssql import MssqlScanner
from hathi.postgres import PostgresScanner
import time
import asyncio

from typing import Dict, List, Optional, Set, Type, Union
from enum import Enum


from rich.console import Console
from rich.table import Table
import json


DEFAULT_TIMEOUT = 1.0  # For initial TCP scan


class HostType(Enum):
    Postgres = "postgres"
    Mssql = "mssql"
    Mysql = "mysql"


console = Console()

DEFAULT_PORTS = {HostType.Postgres: 5432, HostType.Mssql: 1433, HostType.Mysql: 3306}
DEFAULT_DATABASE_NAME = {
    HostType.Postgres: "postgres",
    HostType.Mssql: "master",
    HostType.Mysql: "mysql",
}
SCANNER_CLS: Dict[HostType, Type[Scanner]] = {
    HostType.Postgres: PostgresScanner,
    HostType.Mssql: MssqlScanner,
    HostType.Mysql: MysqlScanner,
}


async def try_hosts(hosts: List[str], types_to_scan: Set[HostType]):
    found = 0
    for host in hosts:
        for host_type in types_to_scan:
            port = DEFAULT_PORTS[host_type]
            try:
                future = asyncio.open_connection(host=host, port=port)
                _, w = await asyncio.wait_for(future, timeout=DEFAULT_TIMEOUT)
                yield host, host_type
                found += 1
                w.close()
            except (asyncio.TimeoutError, OSError):
                pass


async def scan(
    hosts: List[str],
    usernames: Union[List[str], None],
    passwords: str,
    hostname: Optional[str] = None,
    verbose=False,
    multiple: bool = False,
    types_to_scan: Set[HostType] = {HostType.Postgres, HostType.Mssql},
):
    open_hosts = []
    async for open_host in try_hosts(hosts, types_to_scan):
        open_hosts.append(open_host)

    matched_connections = []

    for host, host_type in open_hosts:
        database = DEFAULT_DATABASE_NAME[host_type]
        if verbose:
            console.print(f"[green]Scanning {host} as {host_type}")
        scanner = SCANNER_CLS[host_type](
            host, database, usernames, passwords, hostname, verbose, multiple
        )
        async for match in scanner.scan():
            matched_connections.append(match)

    return matched_connections


def main():
    parser = argparse.ArgumentParser(
        description="Port scan and dictionary attack PostgreSQL, MSSQL and MySQL servers."
    )
    parser.add_argument(
        "hosts", metavar="host", type=str, nargs="+", help="host to scan"
    )
    parser.add_argument("--username", type=str, nargs="+", help="specific username")
    parser.add_argument(
        "--usernames",
        type=str,
        help="Path to plaintext username list file",
        metavar="FILE",
    )
    parser.add_argument(
        "--passwords",
        type=str,
        default="passwords.txt",
        help="Path to plaintext password list file",
        metavar="FILE",
    )
    parser.add_argument(
        "--hostname", type=str, help="an @hostname to append to the usernames"
    )
    parser.add_argument("--json", action="store_true", help="Output in JSON")
    parser.add_argument(
        "--mssql", action="store_true", help="Force scanning hosts as MSSQL"
    )
    parser.add_argument(
        "--postgres", action="store_true", help="Force scanning hosts as Postgres"
    )
    parser.add_argument(
        "--mysql", action="store_true", help="Force scanning hosts as Mysql"
    )
    parser.add_argument(
        "--multiple",
        action="store_true",
        help="Seek multiple username/password pairs on a single host",
    )

    args = parser.parse_args()
    start = time.time()

    if args.mssql:
        types_to_scan = {HostType.Mssql}
    elif args.postgres:
        types_to_scan = {HostType.Postgres}
    elif args.mysql:
        types_to_scan = {HostType.Mysql}
    else:
        types_to_scan = {HostType.Postgres, HostType.Mssql, HostType.Mysql}

    if args.username:
        usernames = args.username
    elif args.usernames:
        with open(args.usernames, "r") as username_list:
            usernames = username_list.readlines()
    else:
        usernames = None

    results = asyncio.run(
        scan(
            args.hosts,
            usernames,
            args.passwords,
            args.hostname,
            verbose=not args.json,
            multiple=args.multiple,
            types_to_scan=types_to_scan,
        )
    )

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "host": result.host,
                        "database": result.database,
                        "username": result.username,
                        "password": result.password,
                        "type": str(result.host_type),
                    }
                    for result in results
                ]
            )
        )
    else:
        table = Table(title="Results")

        table.add_column("Host", justify="right", style="cyan", no_wrap=True)
        table.add_column("Type", justify="right", style="cyan", no_wrap=True)
        table.add_column("Database", style="magenta")
        table.add_column("Username", style="magenta")
        table.add_column("Password", justify="right", style="green")

        for result in results:
            table.add_row(
                result.host,
                str(result.host_type),
                result.database,
                result.username,
                result.password,
            )

        console.print(table)
        console.print("Completed scan in {0} seconds".format(time.time() - start))


if __name__ == "__main__":
    main()
