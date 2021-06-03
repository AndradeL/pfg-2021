#!/bin/bash

make all
for ((i=0;i<20;i++))
do
	make run
done
