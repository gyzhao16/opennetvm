#ifndef PSTACK_H
#define PSTACK_H

#define PSTACK_IP_INFO_SIZE sizeof(_IP_THREAD_LOCAL_P)
#define PSTACK_TCP_INFO_SIZE sizeof(_TCP_THREAD_LOCAL_P)

#include "parallel.h"

struct pstack_thread_info {
    IP_THREAD_LOCAL_P ip_thread_local;
    TCP_THREAD_LOCAL_P tcp_thread_local;
};

void pstack_init(struct pstack_thread_info info, int num_threads);

void* pstack_process(char *data, int len, int rx_queue_id);
void* pstack_locate_state(char *data, int len, int rx_queue_id);
#endif // PSTACK_H