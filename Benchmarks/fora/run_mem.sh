#!/bin/bash

for ((num=2;num<=32;num*=2))
do
	gcc -O3 mem.c -o mem.x -DMBS=$num
	echo "$num MBs copy:" >> mem_times.txt 
	for ((i=0;i<20;i++))
	do
		./mem.x
	done
	echo " " >> mem_times.txt
done