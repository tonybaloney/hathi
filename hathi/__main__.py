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
import asyncio
import ipaddress
import json
import logging
import time
from enum import Enum
from typing import Dict, Generator, List, Optional, Set, Tuple, Type, Union

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn

from hathi.mssql import MssqlScanner
from hathi.mysql import MysqlScanner
from hathi.postgres import PostgresScanner
from hathi.scanner import Scanner

DEFAULT_TIMEOUT = 1.0  # For initial TCP scan

logger = logging.getLogger(__name__)


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


async def try_hosts(
    hosts: List[str], types_to_scan: Set[HostType]
) -> Generator[Tuple[str, HostType, bool], None, None]:
    found = 0
    for host in hosts:
        for host_type in types_to_scan:
            port = DEFAULT_PORTS[host_type]
            try:
                future = asyncio.open_connection(host=host, port=port)
                _, w = await asyncio.wait_for(future, timeout=DEFAULT_TIMEOUT)
                yield host, host_type, True
                found += 1
                w.close()
            except (asyncio.TimeoutError, OSError):
                yield host, host_type, False


async def scan(
    hosts: List[str],
    usernames: Union[List[str], None],
    passwords: str,
    hostname: Optional[str] = None,
    verbose=False,
    multiple: bool = False,
    types_to_scan: Set[HostType] = {HostType.Postgres, HostType.Mssql},
):
    open_hosts: List[Tuple[str, HostType]] = []
    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
    ) as progress:
        t = progress.add_task(
            "Scanning hosts for open ports",
            total=len(hosts) * len(types_to_scan),
            visible=verbose,
        )
        async for host, host_type, is_open in try_hosts(hosts, types_to_scan):
            progress.update(t, advance=1, description=f"Scanning {host}")
            if is_open:
                open_hosts.append((host, host_type))

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
        "hosts", metavar="host", type=str, nargs="*", help="host to scan"
    )
    parser.add_argument("--username", type=str, nargs="+", help="specific username")
    parser.add_argument(
        "--range", type=str, nargs="+", help="CIDR range, e.g. 192.168.1.0/24"
    )
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
    hosts = args.hosts
    if args.range:
        for r in args.range:
            hosts.extend(str(ip) for ip in ipaddress.IPv4Network(r))

    if not hosts:
        logger.error(
            "No hosts scanned, you need to specify the hostnames, or use --range."
        )
        exit()

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
            hosts,
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
