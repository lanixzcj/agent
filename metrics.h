#ifndef METRICS_H
#define METRICS_H 1

#ifndef SYNAPSE_SUCCESS
#define SYNAPSE_SUCCESS 0
#endif
#ifndef SYNAPSE_FAILURE
#define SYNAPSE_FAILURE -1
#endif

#include <sys/types.h>
#include "mon_value.h"
#include "debug_msg.h"
#include "filemonitor.h"

typedef struct {
    char pid[6];
    char state[4];
    char user[16];
    char cpu_usage[4];
    char mem_usage[4];
    char lauch_time[10];
    char running_time[10];
    char command[64];
}PROCESS_INFO;

g_val_t metric_init();
g_val_t cpu_num_func();
g_val_t cpu_speed_func();
g_val_t mem_total_func();
g_val_t swap_total_func();
g_val_t boottime_func();
g_val_t sys_clock_func();
g_val_t machine_type_func();
g_val_t os_name_func();
g_val_t cpu_threshold_func();
g_val_t os_release_func();
g_val_t mtu_func();
g_val_t cpu_user_func();
g_val_t cpu_nice_func();
g_val_t cpu_system_func();
g_val_t cpu_idle_func();
g_val_t cpu_wio_func();
g_val_t cpu_aidle_func();
g_val_t cpu_intr_func();
g_val_t cpu_sintr_func();
g_val_t cpu_steal_func();
g_val_t bytes_in_func();
g_val_t bytes_out_func();
g_val_t pkts_in_func();
g_val_t pkts_out_func();
g_val_t disk_total_func();
g_val_t disk_free_func();
g_val_t part_max_used_func();
g_val_t load_one_func();
g_val_t load_five_func();
g_val_t load_fifteen_func();
g_val_t proc_run_func();
g_val_t proc_total_func();
g_val_t mem_free_func();
g_val_t mem_shared_func();
g_val_t mem_buffers_func();
g_val_t mem_cached_func();
g_val_t swap_free_func();
g_val_t mac_address_func();
g_val_t test_list();
g_val_t test_net_hash();
g_val_t ip_test_func();
g_val_t net_pack_func();
g_val_t cpu_info_func();
g_val_t process_info_func();
g_val_t mem_info_func();
g_val_t disk_info_func();
g_val_t file_log_func();
g_val_t hb_func();
#endif
