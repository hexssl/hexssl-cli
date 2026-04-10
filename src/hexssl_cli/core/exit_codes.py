from enum import IntEnum

from .models import ResultStatus


class ExitCode(IntEnum):
    OK = 0
    CONNECTION_ERROR = 1
    ISSUES_FOUND = 2
    WARNING = 3
    FATAL_ERROR = 4


def status_to_exit_code(status: ResultStatus) -> int:
    mapping = {
        ResultStatus.ok: ExitCode.OK,
        ResultStatus.warning: ExitCode.WARNING,
        ResultStatus.fail: ExitCode.ISSUES_FOUND,
        ResultStatus.error: ExitCode.FATAL_ERROR,
    }
    return int(mapping[status])
