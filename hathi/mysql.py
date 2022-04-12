from typing import Optional, Tuple

from hathi.scanner import Scanner, ScanResult

try:
    from MySQLdb import OperationalError, _mysql

    MYSQL_SUPPORT = True
except ImportError:
    MYSQL_SUPPORT = False

MYSQL_USERNAME_LIST = """
admin
administrator
mysql
superuser
dba
web
website
django
flask
drupal
wordpress
"""


def _mysql_try_host(
    scanner: Scanner,
    host: str,
    username: str,
    password: str,
    database: str,
    no_ssl: Optional[bool],
) -> Tuple[ScanResult, str, str, str]:
    try:
        conn = _mysql.connect(
            host=host,
            user=username,
            passwd=password,
            db=database,
        )
        conn.close()
        return ScanResult.Success, host, username, password
    except OperationalError as oe:
        errno, msg = oe.args
        if errno == 1045:
            return ScanResult.BadPassword, host, username, password
        else:
            return ScanResult.Error, host, username, password


class MysqlScanner(Scanner):
    host_type = "mysql"
    host_connect_func = _mysql_try_host
    default_usernames = MYSQL_USERNAME_LIST
