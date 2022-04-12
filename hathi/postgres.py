import asyncio
import logging
from typing import Optional, Tuple

import asyncpg

from hathi.scanner import Scanner, ScanResult

log = logging.getLogger(__name__)

SSL_MODE = (
    "require"  # require = required, Try SSL first and fallback to non-SSL if failed
)

PG_USERNAME_LIST = """
postgres
admin
administrator
pga
superuser
dba
web
website
django
flask
drupal
wordpress
postgresadmin
"""


async def _pg_try_host(
    scanner: Scanner,
    host: str,
    username: str,
    password: str,
    database: str,
    no_ssl: Optional[bool],
) -> Tuple[ScanResult, str, str, str]:
    try:
        conn = await asyncpg.connect(
            user=username,
            password=password,
            database=database,
            host=host,
            ssl="disable" if no_ssl else "require",
            timeout=5,
        )
        await conn.close()
        return ScanResult.Success, host, username, password
    except asyncpg.exceptions.InvalidPasswordError as exc:
        return ScanResult.BadPassword, host, username, password
    except asyncpg.exceptions.InvalidAuthorizationSpecificationError:
        return ScanResult.BadUsername, host, username, password
    except ConnectionError as exc:
        log.error(exc)
        return ScanResult.Error, host, username, password
    except asyncpg.exceptions._base.PostgresError as exc:
        log.error(exc)
        return ScanResult.Error, host, username, password
    except asyncio.TimeoutError:
        return ScanResult.Timeout, host, username, password


class PostgresScanner(Scanner):
    host_connect_func = _pg_try_host
    host_type = "postgres"
    is_sync = False
    default_usernames = PG_USERNAME_LIST
