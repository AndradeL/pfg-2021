#!/bin/bash

for tests in ./*/
do
    cd $tests
    echo `pwd`
    make clean
    cd ..
done
