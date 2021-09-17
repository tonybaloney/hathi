import asyncio
from collections import namedtuple
from enum import Enum
from typing import List, Optional, Union

from rich.progress import Progress, BarColumn, ProgressColumn, Task
from rich.text import Text

Match = namedtuple("Match", "username password host database data host_type")
from concurrent.futures import ThreadPoolExecutor, as_completed


POOL_SIZE = 10


class LoginAttemptSpeedColumn(ProgressColumn):
    def render(self, task: "Task"):
        """Show data transfer speed."""
        speed = task.finished_speed or task.speed
        if speed is None:
            return Text("?", style="progress.data.speed")
        return Text(f"{speed:.2f} attempt/s", style="progress.data.speed")


class TotalAttemptColumn(ProgressColumn):
    def render(self, task: "Task"):
        return Text(
            f"{task.completed}/{task.total} passwords", style="progress.data.speed"
        )


class ScanResult(Enum):
    Success = 1
    BadPassword = 2
    BadUsername = 3
    Timeout = 4
    Error = 5


def call_async_func(func, host, username, password, database):
    return asyncio.run(func(host, username, password, database))


def call_sync_func(func, host, username, password, database):
    return func(host, username, password, database)


class Scanner:
    host_type = ""
    default_usernames = """"""
    is_sync = True

    def __init__(
        self,
        host: str,
        database: str,
        usernames: Union[List[str], None],
        passwords: str,
        hostname: Optional[str] = None,
        verbose=False,
        multiple=False,
    ):
        self.host = host
        self.database = database
        if usernames:
            self.usernames = usernames
        else:
            self.usernames = [
                un.strip()
                for un in self.default_usernames.splitlines()
                if un.strip() != ""
            ]
        self.passwords = passwords
        self.hostname = hostname
        self.verbose = verbose
        self.multiple = multiple

    async def scan(
        self,
    ):
        with Progress(
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TotalAttemptColumn(),
            LoginAttemptSpeedColumn(),
        ) as progress:

            for _username in self.usernames:
                username = _username.strip()
                if self.hostname:
                    username = f"{username}@{self.hostname}"
                with open(self.passwords, "r") as password_list:
                    _passwords = password_list.readlines()
                    task = progress.add_task(
                        f"[cyan]{_username}",
                        total=len(_passwords),
                        visible=self.verbose,
                    )
                    with ThreadPoolExecutor(max_workers=POOL_SIZE) as executor:
                        login_attempts = [
                            executor.submit(
                                call_sync_func if self.is_sync else call_async_func,
                                self.host_connect_func,
                                self.host,
                                username,
                                password.strip(),
                                self.database,
                            )
                            for password in _passwords
                        ]
                        for future in as_completed(login_attempts):
                            progress.update(task, advance=1)
                            try:
                                result, host, username, password = future.result()
                            except Exception as exc:
                                pass
                            else:
                                if result == ScanResult.Success:
                                    yield Match(
                                        username,
                                        password,
                                        host,
                                        self.database,
                                        {},
                                        self.host_type,
                                    )
                                    if not self.multiple:
                                        executor.shutdown(cancel_futures=True)
                                        progress.stop()
                                        return
                                elif result == ScanResult.BadPassword:
                                    pass
                                elif result == ScanResult.Timeout:
                                    progress.stop()
                                    executor.shutdown(cancel_futures=True)
                                    return
                                elif result == ScanResult.BadUsername:
                                    progress.stop()
                                    executor.shutdown(cancel_futures=True)
                                    break
                                elif result == ScanResult.Error:
                                    progress.stop()
                                    executor.shutdown(cancel_futures=True)
                                    return
