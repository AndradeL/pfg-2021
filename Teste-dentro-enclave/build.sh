#!/bin/bash

for tests in ./*/
do
    cd $tests
    echo `pwd`
    make scons
    make build
    cd ..
done
