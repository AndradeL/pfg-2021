#!/bin/bash

for ((num=1;num<=16;num*=2))
do
	make build NUM=$num
	echo "$num MBs copy:" >> rtimes.txt 
	echo "$num MBs copy:" >> wtimes.txt 
	for ((i=0;i<20;i++))
	do
		make run
        rm copy.txt
	done
	echo " " >> rtimes.txt
	echo " " >> wtimes.txt
done