#!/bin/bash

for ((num=1;num<=16;num*=2))
do
	gcc -O3 disk.c -o disk.x -DMBS=$num
	echo "$num MBs copy:" >> diskr_times.txt 
	echo "$num MBs copy:" >> diskw_times.txt 
	for ((i=0;i<20;i++))
	do
		./disk.x
        rm copy.txt
	done
	echo " " >> diskr_times.txt
	echo " " >> diskw_times.txt
done