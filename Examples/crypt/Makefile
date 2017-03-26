C_APPS=crypt crypt_omp_simple crypt_omp_cu_t crypt_omp_cu_t_target generate_data generate_userkey

all: ${C_APPS}

%: %.c
	gcc -O2 -std=c99 -fopenmp -o $@ $< -lprofiler
clean:
	rm -f ${C_APPS}
