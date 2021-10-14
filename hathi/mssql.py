import os
from typing import Tuple
from hathi.scanner import ScanResult, Scanner

try:
    import pymssql

    MSSQL_SUPPORT = True
except ImportError:
    MSSQL_SUPPORT = False


MSSQL_USERNAME_LIST = """
admin
administrator
superuser
dba
web
website
django
flask
drupal
wordpress
"""


def _mssql_try_host(
    scanner: Scanner, host, username, password, database
) -> Tuple[ScanResult, str, str, str]:
    try:
        conn = pymssql.connect(
            host,
            username,
            password,
            database,
        )
        conn.close()
        return ScanResult.Success, host, username, password
    except pymssql.OperationalError as oe:
        code, *_ = oe.args[0]
        if os.getenv("HATHI_DEBUG", False):
            print(oe.args)
        if code == 18456:
            return ScanResult.BadPassword, host, username, password
        else:
            return ScanResult.Error, host, username, password


class MssqlScanner(Scanner):
    host_type = "mssql"
    host_connect_func = _mssql_try_host
    default_usernames = MSSQL_USERNAME_LIST
