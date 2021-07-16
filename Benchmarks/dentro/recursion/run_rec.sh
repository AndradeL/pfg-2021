#!/bin/bash

for ((num=32;num<=40;num++))
do
	make build NUM=$num
	echo "NUM=$num :" >> times.txt 
	for ((i=0;i<20;i++))
	do
		make run
	done
	echo " " >> times.txt
done