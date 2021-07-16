#!/bin/bash

for ((i=0;i<10;i++))
do
	for tests in ./*/
	do
	    cd $tests
	    echo `pwd`
	    make build
	    cd ..
	done
done
