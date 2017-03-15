C_APPS=crypt crypt_omp_simple crypt_omp_cu generate_data generate_userkey

all: ${C_APPS}

%: %.c
	gcc -O2 -std=c99 -fopenmp -o $@ $<
clean:
	rm -f ${C_APPS}
