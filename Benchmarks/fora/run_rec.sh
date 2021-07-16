#!/bin/bash

for ((num=32;num<=40;num++))
do
	gcc -O3 recursion.c -o recursion.x -DNUM=$num
	echo "NUM=$num :" >> rec_times.txt 
	for ((i=0;i<20;i++))
	do
		./recursion.x
	done
	echo " " >> rec_times.txt
done