#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<malloc.h>
#include<assert.h>
#include<unistd.h>
#include<time.h>
#include<pthread.h>

#include "aho.h"
#include "util.h"
#include "fpp.h"
//add header file
#include "handopt.h"

#define BIG_BATCH_SIZE (32)
#define DEBUG 0

/* Maximum number of patterns a packet can match during its DFA traversal */
#define MAX_MATCH 8192

/* A list of patterns matched by a packet */
struct mp_list_t {
	int num_match;
	uint16_t ptrn_id[MAX_MATCH];
};

/* Sort packets by DFA id. For packets with same dfa_id, sort by length */
static int compare(const void *p1, const void *p2)
{
	const struct aho_pkt *pkt_1 = p1;
	const struct aho_pkt *pkt_2 = p2;

	int dfa_id_diff = pkt_1->dfa_id - pkt_2->dfa_id;
	
	if(dfa_id_diff != 0) {
		return dfa_id_diff;
	}

	int len_diff = pkt_1->len - pkt_2->len;
	return len_diff;
}

static void process_batch_same_dfa(const struct aho_dfa *dfa,
	const struct aho_pkt *pkts, struct mp_list_t *mp_list)
{
	int j = 0, I = 0, state[BATCH_SIZE] = {0};
	struct aho_state *st_arr = dfa->root;

	int max_len = 0;
	for(I = 0; I < BATCH_SIZE; I++) {
		max_len = pkts[I].len > max_len ? pkts[I].len : max_len;
	}

	for(j = 0; j < max_len; j++) {
		for(I = 0; I < BATCH_SIZE; I++) {
			if(j >= pkts[I].len) {
				continue;
			}

			int count = st_arr[state[I]].output.count;

			if(count != 0) {
				/* This state matches some patterns: copy the pattern IDs
				  *  to the output */
				int offset = mp_list[I].num_match;
				memcpy(&mp_list[I].ptrn_id[offset],
					st_arr[state[I]].out_arr, count * sizeof(uint16_t));

				mp_list[I].num_match += count;
			}

			int inp = pkts[I].content[j];
			state[I] = st_arr[state[I]].G[inp];
		}
	}
}

static void process_batch_same_dfa_and_len(const struct aho_dfa *dfa,
	const struct aho_pkt *pkts, struct mp_list_t *mp_list, int len)
{
	int j = 0, I = 0, state[BATCH_SIZE] = {0};
	struct aho_state *st_arr = dfa->root;

	for(j = 0; j < len; j++) {
		for(I = 0; I < BATCH_SIZE; I++) {
			int count = st_arr[state[I]].output.count;

			if(count != 0) {
				/*
				 * This state matches some patterns: copy the pattern IDs
				 * to the output
				 */
				int offset = mp_list[I].num_match;
				memcpy(&mp_list[I].ptrn_id[offset],
					st_arr[state[I]].out_arr, count * sizeof(uint16_t));

				mp_list[I].num_match += count;
			}

			int inp = pkts[I].content[j];
			state[I] = st_arr[state[I]].G[inp];
		}
	}
}

/* Same as noopt's batch-processing function */
static void process_batch_diff(const struct aho_dfa *dfa_arr,
	const struct aho_pkt *pkts, struct mp_list_t *mp_list)
{
	int I, j;

	for(I = 0; I < BATCH_SIZE; I++) {
		int dfa_id = pkts[I].dfa_id;
		int len = pkts[I].len;
		struct aho_state *st_arr = dfa_arr[dfa_id].root;
		
		int state = 0;

		for(j = 0; j < len; j++) {
			int count = st_arr[state].output.count;

			if(count != 0) {
				/*
				 * This state matches some patterns: copy the pattern IDs
				 * to the output
				 */
				int offset = mp_list[I].num_match;
				memcpy(&mp_list[I].ptrn_id[offset],
					st_arr[state].out_arr, count * sizeof(uint16_t));

				mp_list[I].num_match += count;
			}
			int inp = pkts[I].content[j];
			state = st_arr[state].G[inp];
		}
	}
}

static void ids_func(void *ptr)
{
	int i, j, k;

	struct aho_ctrl_blk *cb = (struct aho_ctrl_blk *) ptr;
	struct aho_dfa *dfa_arr = cb->dfa_arr;
	struct aho_pkt *pkts = cb->pkts;
	int num_pkts = cb->num_pkts;

	// red_printf("Starting thread %d\n", id);

	/* Big batch variables */
	int bb_i = 0;
	struct aho_pkt bbatch[BIG_BATCH_SIZE];//  =   malloc(BIG_BATCH_SIZE * sizeof(struct aho_pkt));
	memset(bbatch, 0, BIG_BATCH_SIZE * sizeof(struct aho_pkt));

	/* Per-batch matched patterns */
	struct mp_list_t mp_list[BATCH_SIZE];
	for(i = 0; i < BATCH_SIZE; i++) {
		mp_list[i].num_match = 0;
	}

	/* Being paranoid about GCC optimization: ensure that the memcpys in
	 * process_batch functions don't get optimized out */
	int matched_pat_sum = 0;

	int tot_proc = 0;		/* How many packets did we actually match ? */
	int tot_success = 0;	/* Packets that matched a DFA state */ 
	int tot_bytes = 0;		/* Total bytes matched through DFAs */

	int tot_same_dfa_and_len = 0;
	int tot_same_dfa = 0;
	int tot_diff = 0;

		for(i = 0; i < num_pkts; i++) {

			/* Add the new packet to the big batch */
			bbatch[bb_i] = pkts[i];		/* Shallow copy */
			bb_i++;

			if(bb_i == BIG_BATCH_SIZE) {
				/* The big batch is full */
				qsort(bbatch, BIG_BATCH_SIZE, sizeof(struct aho_pkt), compare);

				for(j = 0; j < BIG_BATCH_SIZE; j += BATCH_SIZE) {
					int same_dfa_and_len = 1, same_dfa = 1;
					int _len = bbatch[j].len;
					int _dfa_id = bbatch[j].dfa_id;

					for(k = j; k < j + BATCH_SIZE; k++) {
						if(bbatch[k].len != _len) {
							same_dfa_and_len = 0;
						}

						if(bbatch[k].dfa_id != _dfa_id) {
							same_dfa_and_len = 0;
							same_dfa = 0;
							break;
						}
					}

					if(same_dfa_and_len == 1) {
						tot_same_dfa_and_len++;
						process_batch_same_dfa_and_len(&dfa_arr[_dfa_id],
							&bbatch[j], mp_list, _len);
					} else if(same_dfa == 1) {
						tot_same_dfa++;
						process_batch_same_dfa(&dfa_arr[_dfa_id],
							&bbatch[j], mp_list);
					} else {
						tot_diff++;
						process_batch_diff(dfa_arr, &bbatch[j], mp_list);
					}

					for(k = 0; k < BATCH_SIZE; k++) {
						int num_match = mp_list[k].num_match;
						assert(num_match < MAX_MATCH);

						tot_success += (num_match == 0 ? 0 : 1);
						tot_proc++;
						tot_bytes += bbatch[j + k].len;

						int pat_i;

						#if DEBUG == 1
						printf("Pkt %d matched: ", bbatch[j + k].pkt_id);

						for(pat_i = 0; pat_i < num_match; pat_i++) {
							printf("%d ", mp_list[k].ptrn_id[pat_i]);
							matched_pat_sum += mp_list[k].ptrn_id[pat_i];
						}

						printf("\n");
						#else
						for(pat_i = 0; pat_i < num_match; pat_i++) {
							matched_pat_sum += mp_list[k].ptrn_id[pat_i];
						}
						#endif

						/* Re-initialize for next iteration */
						mp_list[k].num_match = 0;
					}
				}

				/* Reset big batch index */
				bb_i = 0;
			}
		}

		tot_same_dfa_and_len = 0;
		tot_same_dfa = 0;
		tot_diff = 0;

		matched_pat_sum = 0;	/* Sum of all matched pattern IDs */
		tot_success = 0;
		tot_bytes = 0;
		tot_proc = 0;
}

// static void ids_func(void *ptr)
// {

// 	static int num_display = 0;
// 	num_display ++;
// 	if (num_display == 10){
// 		num_display = 0;
// 	}

// 	int i, j, k;

// 	struct aho_ctrl_blk *cb = (struct aho_ctrl_blk *) ptr;
// 	int id = cb->tid;
// 	struct aho_dfa *dfa_arr = cb->dfa_arr;
// 	struct aho_pkt *pkts = cb->pkts;
// 	int num_pkts = cb->num_pkts;

// 	// red_printf("Starting thread %d\n", id);
// 	printf("Starting thread %d\n", id);

// 	/* Big batch variables */
// 	int bb_i = 0;
// 	struct aho_pkt *bbatch = malloc(BIG_BATCH_SIZE * sizeof(struct aho_pkt));
// 	memset(bbatch, 0, BIG_BATCH_SIZE * sizeof(struct aho_pkt));

// 	/* Per-batch matched patterns */
// 	struct mp_list_t mp_list[BATCH_SIZE];
// 	for(i = 0; i < BATCH_SIZE; i++) {
// 		mp_list[i].num_match = 0;
// 	}

// 	/* Being paranoid about GCC optimization: ensure that the memcpys in
// 	 * process_batch functions don't get optimized out */
// 	int matched_pat_sum = 0;

// 	int tot_proc = 0;		/* How many packets did we actually match ? */
// 	int tot_success = 0;	/* Packets that matched a DFA state */ 
// 	int tot_bytes = 0;		/* Total bytes matched through DFAs */

// 	int tot_same_dfa_and_len = 0;
// 	int tot_same_dfa = 0;
// 	int tot_diff = 0;
// 	printf("num 1\n");
// 	// while(1) {
// 		struct timespec start, end;
// 		clock_gettime(CLOCK_REALTIME, &start);

// 		for(i = 0; i < num_pkts; i++) {
// 			// printf("%d\n", i);
// 			/* Add the new packet to the big batch */
// 			bbatch[bb_i] = pkts[i];		/* Shallow copy */
// 			bb_i++;

// 			// printf("num2\n");
// 			if(bb_i == BIG_BATCH_SIZE) {
// 				/* The big batch is full */
// 				qsort(bbatch, BIG_BATCH_SIZE, sizeof(struct aho_pkt), compare);

// 				for(j = 0; j < BIG_BATCH_SIZE; j += BATCH_SIZE) {
// 					int same_dfa_and_len = 1, same_dfa = 1;
// 					int _len = bbatch[j].len;
// 					int _dfa_id = bbatch[j].dfa_id;

// 					for(k = j; k < j + BATCH_SIZE; k++) {
// 						if(bbatch[k].len != _len) {
// 							same_dfa_and_len = 0;
// 						}

// 						if(bbatch[k].dfa_id != _dfa_id) {
// 							same_dfa_and_len = 0;
// 							same_dfa = 0;
// 							break;
// 						}
// 					}

// 					if(same_dfa_and_len == 1) {
// 						tot_same_dfa_and_len++;
// 						process_batch_same_dfa_and_len(&dfa_arr[_dfa_id],
// 							&bbatch[j], mp_list, _len);
// 					} else if(same_dfa == 1) {
// 						tot_same_dfa++;
// 						process_batch_same_dfa(&dfa_arr[_dfa_id],
// 							&bbatch[j], mp_list);
// 					} else {
// 						tot_diff++;
// 						process_batch_diff(dfa_arr, &bbatch[j], mp_list);
// 					}

// 					for(k = 0; k < BATCH_SIZE; k++) {
// 						int num_match = mp_list[k].num_match;
// 						assert(num_match < MAX_MATCH);

// 						tot_success += (num_match == 0 ? 0 : 1);
// 						tot_proc++;
// 						tot_bytes += bbatch[j + k].len;

// 						int pat_i;

// 						#if DEBUG == 1
// 						printf("Pkt %d matched: ", bbatch[j + k].pkt_id);

// 						for(pat_i = 0; pat_i < num_match; pat_i++) {
// 							printf("%d ", mp_list[k].ptrn_id[pat_i]);
// 							matched_pat_sum += mp_list[k].ptrn_id[pat_i];
// 						}

// 						printf("\n");
// 						#else
// 						for(pat_i = 0; pat_i < num_match; pat_i++) {
// 							matched_pat_sum += mp_list[k].ptrn_id[pat_i];
// 						}
// 						#endif

// 						/* Re-initialize for next iteration */
// 						mp_list[k].num_match = 0;
// 					}
// 				}

// 				/* Reset big batch index */
// 				bb_i = 0;
// 			}
// 		}

// 		clock_gettime(CLOCK_REALTIME, &end);

// 		double ns = (end.tv_sec - start.tv_sec) * 1000000000 +
// 			(double) (end.tv_nsec - start.tv_nsec);

// 		cb->stats[id].tput = (double) (tot_bytes * 8) / ns;

// 		/* Thread 0 prints total throughput, all threads print their own */
// 		if(id == 0) {
// 			double total_rate = 0;
// 			int thread_i = 0;
// 			for(thread_i = 0; thread_i < cb->tot_threads; thread_i++) {
// 				total_rate += cb->stats[thread_i].tput;
// 			}
				
// 			// red_printf("Thread 0: Total rate across all threads = %.2f Gbps. "
// 			// 	"Average rate per thread = %.2f Gbps\n",
// 			// 	total_rate, total_rate / cb->tot_threads);
// 			if (num_display == 0) {
// 				printf("Thread 0: Total rate across all threads = %.2f Gbps. "
// 					"Average rate per thread = %.2f Gbps\n",
// 					total_rate, total_rate / cb->tot_threads);
// 			}
// 		}
// 		if (num_display == 0) {
// 			printf("ID %d: Rate = %.2f Gbps. tot_success = %d\n", id,
// 				((double) tot_bytes * 8) / ns, tot_success);
// 			printf("num_pkts = %d, tot_proc = %d, matched_pat_sum = %d\n"
// 				"same_dfa_and_len %d, same_dfa = %d, diff = %d\n",
// 				num_pkts, tot_proc, matched_pat_sum,
// 				tot_same_dfa_and_len, tot_same_dfa, tot_diff);
// 		}

// 		tot_same_dfa_and_len = 0;
// 		tot_same_dfa = 0;
// 		tot_diff = 0;

// 		matched_pat_sum = 0;	/* Sum of all matched pattern IDs */
// 		tot_success = 0;
// 		tot_bytes = 0;
// 		tot_proc = 0;

// 		// #if DEBUG == 1		 Print matched states only once 
// 		// exit(0);
// 		// #endif
// 	// }

// }

int aho_packet_handler(/*int argc, char *argv[], */struct aho_pkt *pkts, uint16_t num_pkts)
{
	//initialize DFAs during 1st invocation
	static int dfa_init_flag = 0;
	// static int counter = 0;
	// counter ++;
	//add param
	//int argc = 2;
	int i;
	//char *argv[];

	//assert(argc == 2);
	assert(BIG_BATCH_SIZE % BATCH_SIZE == 0);

	//change num of threads
	//int num_threads = atoi(argv[1]);
	int num_threads = 1;
	assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

	struct stat_t *stats = memalign(64, num_threads * sizeof(struct stat_t));
	for(i = 0; i < num_threads; i++) {
		stats[i].tput = 0;
	}

	// static int num_pkts = 1;

	static int num_patterns;

	static struct aho_pattern *patterns;

	//get pkts from simple_forward
	//struct aho_pkt *pkts;

	static struct aho_dfa dfa_arr[AHO_MAX_DFA];

	/* Thread structures */
	// pthread_t worker_threads[AHO_MAX_THREADS];
	// struct aho_ctrl_blk worker_cb[AHO_MAX_THREADS];

	struct aho_ctrl_blk worker_cb;


	// printf("State size = %lu\n", sizeof(struct aho_state));

	if (dfa_init_flag == 0) {

		dfa_init_flag ++;

		/* Initialize the shared DFAs */
		for(i = 0; i < AHO_MAX_DFA; i++) {
			printf("Initializing DFA %d\n", i);
			aho_init(&dfa_arr[i], i);
		}

		printf("Adding patterns to DFAs\n");
		patterns = aho_get_patterns(AHO_PATTERN_FILE,
			&num_patterns);

		for(i = 0; i < num_patterns; i++) {
			int dfa_id = patterns[i].dfa_id;
			aho_add_pattern(&dfa_arr[dfa_id], &patterns[i], i);
		}

		printf("Building AC failure function\n");
		for(i = 0; i < AHO_MAX_DFA; i++) {
			aho_build_ff(&dfa_arr[i]);
			aho_preprocess_dfa(&dfa_arr[i]);
		}
	}
	// if (counter == 10000) {
	// 	printf("Reading another 10000 packets from NetVM\n");
	// 	counter = 0;
	// }

	//get pkts from simple_forward
	//pkts = aho_get_pkts(AHO_PACKET_FILE, &num_pkts);

	// for(i = 0; i < num_threads; i++) {
	// 	worker_cb[i].stats = stats;
	// 	worker_cb[i].tot_threads = num_threads;
	// 	worker_cb[i].tid = i;
	// 	worker_cb[i].dfa_arr = dfa_arr;
	// 	//
	// 	worker_cb[i].pkts = pkts;
	// 	worker_cb[i].num_pkts = num_pkts;

	// 	pthread_create(&worker_threads[i], NULL, ids_func, &worker_cb[i]);

	// 	/* Ensure that threads don't use the same packets close in time */
	// 	sleep(2);
	// }
	worker_cb.stats = stats;
	worker_cb.tid = 0;
	worker_cb.dfa_arr = dfa_arr;
	worker_cb.pkts = pkts;
	worker_cb.num_pkts = num_pkts;
	ids_func(&worker_cb);

	// for(i = 0; i < num_threads; i++) {
	// 	pthread_join(worker_threads[i], NULL);
	// }

	/* The work never ends */
	//assert(0);

	return 0;
}
