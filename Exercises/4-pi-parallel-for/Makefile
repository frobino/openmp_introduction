CC=gcc

all: pi.x

pi.x: pi.o
	${CC} -fopenmp pi.o -o pi.x 

pi.o: pi.c
	${CC} -c -fopenmp pi.c

clean:
	rm -rf *.o *.x *~
