#!/bin/bash

cleanup()
{
	echo "Test failed"
	exit 1
}

scons || cleanup 
./test.exe ./test.exe || cleanup 
./test.exe /bin/ls || cleanup 
./test.exe /bin/bash || cleanup 

echo "test passed"
exit 0
