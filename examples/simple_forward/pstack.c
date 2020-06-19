#include "nids.h"
#include "pstack.h"

void pstack_init(struct pstack_thread_info info, int num_threads) {
    nids_lib_init(num_threads, info.ip_thread_local, info.tcp_thread_local);
}

inline void* pstack_process(char *data, int len, int rx_queue_id) {
    return gen_ip_frag_proc(data, len, rx_queue_id);
}

inline void* pstack_locate_state(char *data, int len, int rx_queue_id) {
    return simulate_locate_state(data, len, rx_queue_id);
}

