#!/bin/bash

for ((i=0;i<20;i++))
do
	for tests in ./*/
	do
	    cd $tests
	    echo `pwd`
	    make run
	    cd ..
	done
done
