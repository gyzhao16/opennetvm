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
 * forward.c - an example using onvm. Forwards packets to a DST NF.
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

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

//add aho-corasick
#include "aho.h"
#include "util.h"
#include "fpp.h"
#include "handopt.h"
#include "pstack.h"

#define NF_TAG "nids"

/* number of package between each print */
static uint32_t print_delay = 100000000;

static uint32_t destination;
static uint16_t num_children = 0;
static uint16_t use_shared_core_allocation = 0;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d <dst>`: destination service ID to foward to\n");
        printf(" - `-n NUM_CHILDREN`: Sets the number of children for the NF to spawn\n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:n:p:")) != -1) {
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                dst_flag = 1;
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case 'n':
                                num_children = strtoul(optarg, NULL, 10);
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

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Simple Forward NF requires destination flag -d.\n");
                return -1;
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

#define MAX_BATCH_SIZE 32

static int 
packet_bulk_handler(struct rte_mbuf **pkts, uint16_t nb_pkts, 
                    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    static uint32_t counter = 0;
    struct aho_pkt aho_pkts[MAX_BATCH_SIZE];

    int i = 0;
    struct onvm_pkt_meta *meta;
    uint8_t *pkt_data = NULL;
    // printf("this is bulk function\n");
    counter += nb_pkts;
    if (counter >= 10000000) {
        do_stats_display(pkts[i]);
        counter = 0;
    }
    // printf("%d\n", nb_pkts);
    RTE_ASSERT(nb_pkts <= MAX_BATCH_SIZE);
    
    for (i = 0; i < nb_pkts; i++) {
        struct ipv4_hdr* ipv4_hdr = onvm_pkt_ipv4_hdr(pkts[i]);
        if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
                struct tcp_hdr *tcp = onvm_pkt_tcp_hdr(pkts[i]);
                pkt_data = ((uint8_t *)tcp) + sizeof(struct tcp_hdr);
        } else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
                struct udp_hdr *udp = onvm_pkt_udp_hdr(pkts[i]);
                pkt_data = ((uint8_t *)udp) + sizeof(struct udp_hdr);
        }
        if (pkt_data != NULL) {
            uint8_t *eth;
            uint16_t plen;
            uint16_t hlen;

            //calculate length
            eth = rte_pktmbuf_mtod(pkts[i], uint8_t *);
            hlen = pkt_data - eth;
            plen = pkts[i]->pkt_len - hlen;

            aho_pkts[i].pkt_id = i;
            aho_pkts[i].dfa_id = 0;
            aho_pkts[i].len = plen;
            aho_pkts[i].content = pkt_data;
        }

        meta = onvm_get_pkt_meta((struct rte_mbuf *)pkts[i]);
        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;
    }

    aho_packet_handler(aho_pkts, nb_pkts);
    return 0;
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        
        //initialize DFAs during 1st invocation
        
        // static int dfa_init_flag = 0;
        // static int num_patterns, i;
        // static struct aho_pattern *patterns;
        // static struct aho_dfa dfa_arr[AHO_MAX_DFA];

        // if (dfa_init_flag == 0) {
        //     dfa_init_flag ++;
        //     for(i = 0; i < AHO_MAX_DFA; i++) {
        //         printf("Initializing DFA %d\n", i);
        //         aho_init(&dfa_arr[i], i);
        //     }
            
        //     printf("Adding patterns to DFAs\n");
        //     patterns = aho_get_patterns(AHO_PATTERN_FILE, 
        //         &num_patterns);
            
        //     for(i = 0; i < num_patterns; i++) {
        //         int dfa_id = patterns[i].dfa_id;
        //         aho_add_pattern(&dfa_arr[dfa_id], &patterns[i], i);
        //     }
            
        //     printf("Building AC failure function\n");
        //     for(i = 0; i < AHO_MAX_DFA; i++) {
        //         aho_build_ff(&dfa_arr[i]);
        //         aho_preprocess_dfa(&dfa_arr[i]);
        //     }
        // }
        //printf("this is packet packet_handler\n");
        static uint32_t counter = 0;
        if (++counter == print_delay) {
                do_stats_display(pkt);
                printf("this is %d packets\n", print_delay);
                counter = 0;
        }
        uint16_t num_pkts = 1;
        // check udp packet
        struct udp_hdr *udp;
        udp = onvm_pkt_udp_hdr(pkt);
        if (udp != NULL) {
            uint8_t *pkt_data;
            uint8_t *eth;
            uint16_t plen;
            uint16_t hlen;

            //get at the payload
            pkt_data = ((uint8_t *)udp) + sizeof(struct udp_hdr);
            //calculate length
            eth = rte_pktmbuf_mtod(pkt, uint8_t *);
            hlen = pkt_data - eth;
            plen = pkt->pkt_len - hlen;

            //aho-corasick
            struct aho_pkt pkts;
            pkts.pkt_id = 0;
            pkts.dfa_id = 0;
            pkts.len = plen;
            pkts.content = pkt_data;
            // printf("%s\n", pkt_data);
            aho_packet_handler(&pkts, num_pkts);
        }

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;
        return 0;
}

static int
packet_bulk_handler_with_scaling(struct rte_mbuf **pkts, uint16_t nb_pkts,
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
                scale_info->function_table->pkt_bulk_handler = &packet_bulk_handler;
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

        return packet_bulk_handler(pkts, nb_pkts, nf_local_ctx);
}

static struct pstack_thread_info pstack_info; 

static void init_pstack(void) {
        pstack_info.ip_thread_local = (IP_THREAD_LOCAL_P) rte_malloc(PSTACK_IP_INFO_NAME, 10 * PSTACK_IP_INFO_SIZE, 0);
	pstack_info.tcp_thread_local = (TCP_THREAD_LOCAL_P) rte_malloc(PSTACK_TCP_INFO_NAME, 10 * PSTACK_TCP_INFO_SIZE, 0);
        // RTE_ASSERT(pstack_info.ip_thread_local != NULL && pstack_info.tcp_thread_local != NULL);
        // pstack_info.ip_thread_local = malloc((MAX_CPU_CORES - 1) * PSTACK_IP_INFO_SIZE);
	// pstack_info.tcp_thread_local = malloc((MAX_CPU_CORES - 1) * PSTACK_TCP_INFO_SIZE);

	pstack_init(pstack_info, 9);
}

int
main(int argc, char *argv[]) {
    
        //original main function
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;

        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        nf_function_table->pkt_bulk_handler = &packet_bulk_handler_with_scaling;
        // nf_function_table->pkt_bulk_handler = &packet_bulk_handler;

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

        RTE_SET_USED(init_pstack);
        // init_pstack();

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
