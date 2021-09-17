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
    except pymssql.OperationalError:
        return ScanResult.BadPassword, host, username, password


class MssqlScanner(Scanner):
    host_type = "mssql"
    host_connect_func = _mssql_try_host
    default_usernames = MSSQL_USERNAME_LIST
