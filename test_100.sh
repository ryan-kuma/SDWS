#!/bin/bash
i=1
while [ $i -le 100 ]
do
	./client 101.34.189.108 12359 
	let 'i++'
done
