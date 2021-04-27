#!/bin/bash

for tests in ./*/
do
    cd $tests
    echo `pwd`
    make build
    make run
    cd ..
done