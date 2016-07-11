#!/bin/bash
set -e

# Get required parameters.
HOST=${1}
BIND_DN=${2}
BIND_PASS=${3}

# Requirement: sudo apt-get install ldap-utils
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./groups.ldif -c
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./users.ldif -c

ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./users/1001_stanley101.ldif -c
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./groups/testers_unique.ldif -c
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./assignment/stanley101.ldif -c

ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./users/1002_stanley102.ldif -c
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./groups/testers_nonunique.ldif -c
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./assignment/stanley102.ldif -c

ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./users/1003_stanley103.ldif -c
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./groups/testers_posix.ldif -c
ldapadd -h ${HOST} -x -D ${BIND_DN} -w ${BIND_PASS} -f ./assignment/stanley103.ldif -c
