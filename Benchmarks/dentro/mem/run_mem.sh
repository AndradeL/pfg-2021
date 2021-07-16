#!/bin/bash

for ((num=2;num<=32;num*=2))
do
	make build -DNUM=$num
	echo "==== $num MBs copy:" >> times.txt 
	for ((i=0;i<20;i++))
	do
		make run
	done
	echo " " >> times.txt
done