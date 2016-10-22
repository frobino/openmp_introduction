CC=gcc

all: helloworld.x

helloworld.x: main.o
	${CC} -fopenmp main.o -o helloworld.x 

main.o: main.c
	${CC} -c -fopenmp main.c

clean:
	rm -rf *.o *.x *~
