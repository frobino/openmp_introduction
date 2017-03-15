C_APPS=crypt generate_data generate_userkey

all: ${C_APPS}

%: %.c
	gcc -O2 -std=c99 -fopenmp -o $@ $<
clean:
	rm -f ${C_APPS}
