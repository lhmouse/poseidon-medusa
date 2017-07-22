#!/bin/bash

_runpath="$(find $(pwd) -path '*/lib/.libs' -type d -print0 | sed -r 's/\x00/:/g')"
_confpath="$(pwd)/etc/poseidon-medusa2"

if [ "$1" == "-d" ]; then
	LD_LIBRARY_PATH="${_runpath}" ./libtool --mode=execute gdb --args poseidon "${_confpath}"
elif [ "$1" == "-v" ]; then
	LD_LIBRARY_PATH="${_runpath}" ./libtool --mode=execute valgrind --leak-check=full --log-file='valgrind.log' poseidon "${_confpath}"
elif [ "$1" == "-vgdb" ]; then
	LD_LIBRARY_PATH="${_runpath}" ./libtool --mode=execute valgrind --vgdb=yes --vgdb-error=0 --leak-check=full --log-file='valgrind.log' poseidon "${_confpath}"
else
	LD_LIBRARY_PATH="${_runpath}" poseidon "${_confpath}"
fi
