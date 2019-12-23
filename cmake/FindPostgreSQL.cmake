
# - Try to find the PostgreSQL libraries
#
#  POSTGRESQL_INCLUDE_DIR - PostgreSQL include directory
#  POSTGRESQL_LIBRARY     - PostgreSQL library
#  PQ_LIBRARY             - PostgreSQL PQ library

find_path(
    POSTGRESQL_INCLUDE_DIR
    NAMES common/base64.h common/saslprep.h common/scram-common.h common/sha2.h
    PATH_SUFFIXES PG_INCLUDE_SERVER
)

option(PG_VERSION_NUM "PostgreSQL version" 100000)

execute_process (
        COMMAND pg_config --libdir
        OUTPUT_VARIABLE PG_LIBDIR
)

execute_process (
        COMMAND pg_config --pkglibdir
        OUTPUT_VARIABLE PG_PKGLIBDIR
)

execute_process (
        COMMAND pg_config --includedir-server
        OUTPUT_VARIABLE PG_INCLUDE_SERVER
)

set(POSTGRESQL_INCLUDE_DIR ${PG_INCLUDE_SERVER})

find_library(
    POSTGRESQL_LIBRARY
    NAMES pgcommon
    HINTS ${PG_LIBDIR} ${PG_PKGLIBDIR} /usr/lib/postgresql/10/lib
)

find_library(
    POSTGRESQL_LIBPGPORT
    NAMES pgport
    HINTS ${PG_LIBDIR}  ${PG_PKGLIBDIR} /usr/lib/postgresql/10/lib
)

find_library(
    PQ_LIBRARY
    NAMES libpq.a
)

find_package_handle_standard_args(
    POSTGRESQL
    REQUIRED_VARS POSTGRESQL_LIBRARY PQ_LIBRARY POSTGRESQL_INCLUDE_DIR
)
