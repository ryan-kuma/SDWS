#!/bin/bash
i=1
while [ $i -le 1000 ]
do
	./client 127.0.0.1 12359 
	let 'i++'
done
