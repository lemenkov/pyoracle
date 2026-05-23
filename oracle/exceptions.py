# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

# PEP 249 (DB-API 2.0) exception hierarchy.
#
#   StandardError                          (built-in Exception)
#    |__ Warning
#    |__ Error
#         |__ InterfaceError
#         |__ DatabaseError
#              |__ DataError
#              |__ OperationalError
#              |__ IntegrityError
#              |__ InternalError
#              |__ ProgrammingError
#              |__ NotSupportedError


class Warning(Exception):
    pass


class Error(Exception):
    pass


class InterfaceError(Error):
    pass


class DatabaseError(Error):

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class DataError(DatabaseError):
    pass


class OperationalError(DatabaseError):
    pass


class IntegrityError(DatabaseError):
    pass


class InternalError(DatabaseError):
    pass


class ProgrammingError(DatabaseError):
    pass


class NotSupportedError(DatabaseError):
    pass
