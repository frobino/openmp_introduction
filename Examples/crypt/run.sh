#!/bin/bash

DATA=data8M

./crypt encrypt ${DATA} ${DATA}en key
./crypt decrypt ${DATA}en ${DATA}de key
