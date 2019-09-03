#!/bin/bash

set -e 
set -x


function main()
{
	cd /tmp/libehp_test
	scons -j3
	cd test
	./test.sh
	exit 0
}

main "$@"
