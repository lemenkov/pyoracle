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


# Mapping from Oracle ORA-NNNNN error codes to the right PEP 249
# subclass. Drawn from public Oracle docs; we are NOT embedding
# Oracle's message text (clean-room boundary), only the code → class
# mapping. Codes not listed here surface as the base `DatabaseError`,
# matching pre-mapping behaviour.
_ORA_CODE_TO_CLASS: dict[int, type[DatabaseError]] = {
    # IntegrityError — constraint violations
    1: IntegrityError,        # unique constraint violated
    1400: IntegrityError,     # cannot insert NULL into not-null column
    1407: IntegrityError,     # cannot update to NULL
    2290: IntegrityError,     # check constraint violated
    2291: IntegrityError,     # parent key not found (FK)
    2292: IntegrityError,     # child record found (FK)

    # DataError — value-out-of-range / conversion problems
    1438: DataError,          # value larger than column precision allows
    1722: DataError,          # invalid number
    1830: DataError,          # date format picture ends before whole string
    1839: DataError,          # date not valid for month specified
    1841: DataError,          # full year must be between -4713 and +9999
    1843: DataError,          # not a valid month
    1847: DataError,          # day of month must be between 1 and last day
    1858: DataError,          # non-numeric character where numeric expected
    1861: DataError,          # literal does not match format string
    6502: DataError,          # PL/SQL numeric or value error

    # ProgrammingError — bad SQL or schema use
    900: ProgrammingError,    # invalid SQL statement
    903: ProgrammingError,    # invalid table name
    904: ProgrammingError,    # invalid identifier
    905: ProgrammingError,    # missing keyword
    906: ProgrammingError,    # missing left parenthesis
    907: ProgrammingError,    # missing right parenthesis
    909: ProgrammingError,    # invalid number of arguments
    911: ProgrammingError,    # invalid character
    917: ProgrammingError,    # missing comma
    920: ProgrammingError,    # invalid relational operator
    923: ProgrammingError,    # FROM keyword not found where expected
    933: ProgrammingError,    # SQL command not properly ended
    936: ProgrammingError,    # missing expression
    942: ProgrammingError,    # table or view does not exist
    955: ProgrammingError,    # name is already used by an existing object
    1008: ProgrammingError,   # not all variables bound
    1031: ProgrammingError,   # insufficient privileges
    1745: ProgrammingError,   # invalid host/bind variable name
    1747: ProgrammingError,   # invalid column specification
    1756: ProgrammingError,   # quoted string not properly terminated

    # OperationalError — transient / network / runtime problems
    1013: OperationalError,   # user requested cancel of current operation
    3113: OperationalError,   # end-of-file on communication channel
    3114: OperationalError,   # not connected to ORACLE
    3135: OperationalError,   # connection lost contact
    12170: OperationalError,  # TNS:Connect timeout occurred
    12505: OperationalError,  # TNS:listener does not currently know of SID
    12514: OperationalError,  # TNS:listener does not currently know of service
    12541: OperationalError,  # TNS:no listener
    12543: OperationalError,  # TNS:destination host unreachable
    12545: OperationalError,  # Connect failed because target host or object
    12560: OperationalError,  # TNS:protocol adapter error
}


def from_ora_code(code: int) -> type[DatabaseError]:
    """Return the PEP 249 subclass corresponding to an ORA error code.

    Codes without a mapping fall back to the base `DatabaseError`.
    """
    return _ORA_CODE_TO_CLASS.get(code, DatabaseError)
