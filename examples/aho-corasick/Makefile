all:
	gcc -O3 -o handopt aho.c ds_queue.c handopt.c util.c -lpapi -Wno-unused-result -lrt -lpthread -Wall -Werror -march=native -fgnu89-inline
	gcc -O3 -o noopt aho.c ds_queue.c noopt.c util.c -lpapi -Wno-unused-result -lrt -lpthread -Wall -Werror -fgnu89-inline
clean:
	rm handopt noopt
