/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *            2016-2019 Hewlett Packard Enterprise Development LP
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
 * aesencrypt.c - Encrypt UDP packets using AES
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
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include "aes.h"
#include "hmac.h"
#include "sha.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "aes_encrypt"

/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t destination;

/* AES encryption parameters */
BYTE key[1][32] = {{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}};
BYTE iv[1][16] = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};
WORD key_schedule[60];  // word Schedule

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
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                dst_flag = 1;
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

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "AES Encrypt NF requires destination flag -d.\n");
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
                struct udp_hdr *udp;

                onvm_pkt_print(pkt);
                /* Check if we have a valid UDP packet */
                udp = onvm_pkt_udp_hdr(pkt);
                if (udp != NULL) {
                        uint8_t *pkt_data;
                        pkt_data = ((uint8_t *)udp) + sizeof(struct udp_hdr);
                        printf("Payload : %.32s\n", pkt_data);
                }
        } else {
                printf("No IP4 header found\n");
        }
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        struct udp_hdr *udp;
        uint8_t hmac_out[SHA1_DIGEST_SIZE];
        size_t hmac_len = 0;
        static uint32_t counter = 0;

        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        /* Check if we have a valid UDP packet */
        udp = onvm_pkt_udp_hdr(pkt);
        if (udp != NULL) {
                uint8_t *pkt_data;
                uint8_t *eth;
                uint16_t plen;
                uint16_t hlen;

                /* Get at the payload */
                pkt_data = ((uint8_t *)udp) + sizeof(struct udp_hdr);
                /* Calculate length */
                eth = rte_pktmbuf_mtod(pkt, uint8_t *);
                hlen = pkt_data - eth;
                plen = pkt->pkt_len - hlen;

                /* Encrypt. */
                /* IV should change with every packet, but we don't have any
                 * way to send it to the other side. */
                aes_encrypt_ctr(pkt_data, plen, pkt_data, key_schedule, 256, iv[0]);
                hmac_sha1(key[0], 32, pkt_data, plen, hmac_out, &hmac_len);
                if (counter == 0) {
                        printf("Encrypted %d bytes at offset %d (%ld)\n", plen, hlen,
                               sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
                }
        }

        meta->action = ONVM_NF_ACTION_TONF;
        meta->destination = destination;
        return 0;
}

int packet_bulk_handler(struct rte_mbuf **pkt, uint16_t nb_pkts,
                                 __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
                static uint32_t counter = 0;
        struct udp_hdr *udp;
        struct onvm_pkt_meta *meta;
        uint8_t hmac_out[SHA1_DIGEST_SIZE];
        size_t hmac_len = 0;
        int i = 0;

        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }
        for (i = 0; i < nb_pkts; i++) {
                meta = onvm_get_pkt_meta(pkt[i]);
                /* Check if we have a valid UDP packet */
                udp = onvm_pkt_udp_hdr(pkt[i]);
                if (udp != NULL) {
                        uint8_t *pkt_data;
                        uint8_t *eth;
                        uint16_t plen;
                        uint16_t hlen;

                /* Get at the payload */
                        pkt_data = ((uint8_t *)udp) + sizeof(struct udp_hdr);
                /* Calculate length */
                        eth = rte_pktmbuf_mtod(pkt[i], uint8_t *);
                        hlen = pkt_data - eth;
                        plen = pkt[i]->pkt_len - hlen;

                /* Encrypt. */
                /* IV should change with every packet, but we don't have any
                 * way to send it to the other side. */
                        aes_encrypt_ctr(pkt_data, plen, pkt_data, key_schedule, 256, iv[0]);
                        hmac_sha1(key[0], 32, pkt_data, plen, hmac_out, &hmac_len);
                        if (counter == 0) {
                                printf("Encrypted %d bytes at offset %d (%ld)\n", plen, hlen,
                                       sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr));
                        }
                }
                meta->action = ONVM_NF_ACTION_TONF;
                meta->destination = destination;
        }
        return 0;
}

int
main(int argc, char *argv[]) {
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        int arg_offset;

        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;
        nf_function_table->pkt_bulk_handler = &packet_bulk_handler;

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

        /* Initialise encryption engine. Key should be configurable. */
        aes_key_setup(key[0], key_schedule, 256);

        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);
        printf("If we reach here, program is ending\n");
        return 0;
}
