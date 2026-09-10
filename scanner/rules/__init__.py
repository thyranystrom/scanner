from collections.abc import Callable

from .ajax import scan_ajax
from .auth import scan_rest_and_admin
from .dangerous_functions import scan_dangerous
from .input import scan_input
from .output import scan_output
from .owasp_top10 import scan_owasp_top10
from .secrets import scan_secrets
from .sql import scan_sql

RULES: list[Callable] = [
    scan_ajax,
    scan_rest_and_admin,
    scan_input,
    scan_sql,
    scan_output,
    scan_secrets,
    scan_dangerous,
    scan_owasp_top10,
]
