#!/bin/bash

DATA=data1K

./crypt encrypt ${DATA} ${DATA}en key
./crypt decrypt ${DATA}en ${DATA}de key
