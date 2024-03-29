/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * nf_router.c - route packets based on the provided config.
 ********************************************************************/

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_arp.h>
#include <rte_common.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_lpm.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "router"

/* router information */
uint8_t nf_count;
char *cfg_filename;
struct forward_nf *fwd_nf;

struct forward_nf {
        uint32_t ip;
        uint8_t dest;
};

/* number of package between each print */
static uint32_t print_delay = 1000000;

/* alloc a simple tbl24 for routing */
static uint16_t tbl24[1 << 24];
int destination;
static uint16_t num_children = 0;
static uint16_t use_shared_core_allocation = 0;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- <router_config> -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d DST`: Destination Service ID to forward to\n");
        printf(" - `-n NUM_CHILDREN`: Sets the number of children for the NF to spawn\n");
        // printf(" - `-f <router_cfg>`: router configuration, has a list of (IPs, dest) tuples \n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c = 0;

        while ((c = getopt(argc, argv, "d:n:p:")) != -1) {
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                break;
                        // case 'f':
                        //         cfg_filename = strdup(optarg);
                        //         break;
                        case 'n':
                                num_children = strtoul(optarg, NULL, 10);
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }

        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf *pkt) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        static uint64_t pkt_process = 0;
        struct ipv4_hdr *ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %" PRIu64 "\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        struct ipv4_hdr *ip;

        uint32_t hash;
        uint16_t res;

        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }
        
        ip = onvm_pkt_ipv4_hdr(pkt);

        RTE_ASSERT(ip != NULL);

        // just query the table
        hash = (ip->dst_addr) >> 8;
        res = tbl24[hash];
        (void) res;

        meta->destination = destination;
        meta->action = ONVM_NF_ACTION_TONF;
        return 0;
}

static int
packet_bulk_handler(struct rte_mbuf **pkts, uint16_t nb_pkts,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        struct ipv4_hdr *ip;
        int i;
        uint32_t hash;
        uint16_t res;
        struct onvm_pkt_meta *meta;

        counter += nb_pkts;

        if (counter == print_delay) {
                do_stats_display(pkts[0]);
                counter = 0;
        }

        for (i = 0; i < nb_pkts; i++) {
                ip = onvm_pkt_ipv4_hdr(pkts[i]);
                meta = onvm_get_pkt_meta(pkts[i]);
                RTE_ASSERT(ip != NULL);
                hash = (ip->dst_addr) >> 8;
                res = tbl24[hash];
                (void) res;

                meta->destination = destination;
                if (destination == 0) {
                        meta->action = ONVM_NF_ACTION_OUT;
                } else {
                        meta->action = ONVM_NF_ACTION_TONF;
                }
        }
        return 0;
}

static int
packet_bulk_handler_opt(struct rte_mbuf **pkts, uint16_t nb_pkts,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
	static uint32_t counter;
	struct ipv4_hdr *ip[MAX_BATCH_SIZE];
        uint32_t hash[BATCH_SIZE];
	uint16_t res[MAX_BATCH_SIZE];
	struct onvm_pkt_meta *meta[MAX_BATCH_SIZE];

	int I = 0;			// batch index
	void *batch_rips[MAX_BATCH_SIZE];		// goto targets
	int iMask = 0;		// No packet is done yet

	int temp_index;
	for(temp_index = 0; temp_index < MAX_BATCH_SIZE; temp_index ++) {
		batch_rips[temp_index] = &&fpp_start;
	}
	counter = 0;
        counter += nb_pkts;

        if (counter == print_delay) {
                do_stats_display(pkts[0]);
                counter = 0;
        }

fpp_start:
        FPP_PSS(pkts[I], fpp_label_1, nb_pkts);
fpp_label_1:
        ip[I] = onvm_pkt_ipv4_hdr(pkts[I]);
        meta[I] = onvm_get_pkt_meta(pkts[I]);
        hash[I] = (ip[I]->dst_addr) >> 8;
        RTE_ASSERT(ip[I] != NULL);
        FPP_PSS(&tbl24[hash[I]], fpp_label_2, nb_pkts);
fpp_label_2:
        res[I] = tbl24[hash[I]];
        (void) res[I];

        meta[I]->destination = destination;
        if (destination == 0) {
                meta[I]->action = ONVM_NF_ACTION_OUT;
        } else {
                meta[I]->action = ONVM_NF_ACTION_TONF;
        }
fpp_end:
	batch_rips[I] = &&fpp_end;
	iMask = FPP_SET(iMask, I);
	if(iMask == (nb_pkts < MAX_BATCH_SIZE ? (1 << nb_pkts) - 1 : -1)) {
		return 0;
	}
	I = (I + 1) < nb_pkts ? I + 1 : 0;
	goto *batch_rips[I];
}

static int
packet_bulk_handler_opt_with_scaling(struct rte_mbuf **pkts, uint16_t nb_pkts,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t spawned_nfs = 0;

        /* Spawn children until we hit the set number */
        while (spawned_nfs < num_children) {
                struct onvm_nf_scale_info *scale_info = onvm_nflib_get_empty_scaling_config(nf_local_ctx->nf);
                /* Sets service id of child */
                scale_info->nf_init_cfg->service_id = nf_local_ctx->nf->service_id;
                scale_info->function_table = onvm_nflib_init_nf_function_table();
                /* Custom packet handler */
                scale_info->function_table->pkt_handler = &packet_handler;
                scale_info->function_table->pkt_bulk_handler = &packet_bulk_handler_opt;
                if (use_shared_core_allocation)
                        scale_info->nf_init_cfg->init_options = ONVM_SET_BIT(0, SHARE_CORE_BIT);

                /* Spawn the child */
                if (onvm_nflib_scale(scale_info) == 0)
                        RTE_LOG(INFO, APP, "Spawning child SID %u; with packet_handler_fwd packet function\n",
                                scale_info->nf_init_cfg->service_id);
                else
                        rte_exit(EXIT_FAILURE, "Can't spawn child\n");
                spawned_nfs++;
        }

        return packet_bulk_handler_opt(pkts, nb_pkts, nf_local_ctx);
}

int
main(int argc, char *argv[]) {
        int arg_offset;
        int i;
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        RTE_SET_USED(packet_bulk_handler);
        RTE_SET_USED(packet_bulk_handler_opt);
        nf_function_table->pkt_bulk_handler = &packet_bulk_handler_opt_with_scaling;

        // initiate table
        for (i = 0; i < (1 << 24); i++) {
                tbl24[i] = i & 0xFFFF;
        }

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        // parse_router_config();

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
