from typing import Tuple
from hathi.scanner import ScanResult, Scanner

try:
    from MySQLdb import _mysql, OperationalError

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
    scanner: Scanner, host, username, password, database
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
