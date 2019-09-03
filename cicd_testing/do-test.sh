#!/bin/bash

set -e 
set -x


function main()
{
	scons -j3
	cd test
	./test.sh || exit 1
	exit 0
}

main "$@"
