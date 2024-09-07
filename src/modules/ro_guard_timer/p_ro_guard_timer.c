// Copyright (C) 2021-2024, HardenedVault (https://hardenedvault.net)

#include "../../p_lkrg_main.h"


struct timer_list ro_guard_timer;


struct ro_data {

    unsigned long  *mmap_min_addr_p;
    unsigned long mmap_min_addr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    int *kptr_restrict_p;
    int kptr_restrict;
#endif

    bool *kprobes_all_disarmed_p;
    bool kprobes_all_disarmed;

};
static struct ro_data ved_ro_data;


void ro_data_init(struct ro_data* ro_data) {

    ro_data->mmap_min_addr_p = (unsigned long*)P_SYM(p_kallsyms_lookup_name)("mmap_min_addr");
    if (!ro_data->mmap_min_addr_p) {
        p_print_log(P_LOG_FAULT, "ro_guard could not check mmap_min_addr\n");
    } else {
        ro_data->mmap_min_addr = *ro_data->mmap_min_addr_p;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    ro_data->kptr_restrict_p = (int*)P_SYM(p_kallsyms_lookup_name)("kptr_restrict");
    if (!ro_data->kptr_restrict_p)
        p_print_log(P_LOG_FAULT, "ro_guard could not check kptr_restrict\n");
    else
        ro_data->kptr_restrict = *ro_data->kptr_restrict;
#endif

    ro_data->kprobes_all_disarmed_p = (bool*)P_SYM(p_kallsyms_lookup_name)("kprobes_all_disarmed");
    if (!ro_data->kprobes_all_disarmed_p)
        p_print_log(P_LOG_FAULT, "ro_guard could not check kprobe_all_disarmed\n");
    else
        ro_data->kprobes_all_disarmed = *ro_data->kprobes_all_disarmed_p;

}


void global_ro_data_check(struct ro_data* ro_data) {

    if (ro_data->mmap_min_addr_p
    && *ro_data->mmap_min_addr_p != ro_data->mmap_min_addr)
        p_print_log(P_LOG_FAULT, "mmap_min_addr may be corrupted\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    if (ro_data->kptr_restrict_p
    && *ro_data->kptr_restrict_p != ro_data->kptr_restrict)
        p_print_log(P_LOG_FAULT, "kptr_restrict may be corrupted\n");
#endif

    if (ro_data->kprobes_all_disarmed_p
     && *ro_data->kprobes_all_disarmed_p != ro_data->kprobes_all_disarmed) {
        p_print_log(P_LOG_FAULT, "all kprobe was disable, VED was disarmed\n");
        p_offload_work(0);
    }

}


void kprobe_check(void) {

    p_kprobes_disabled_warn(P_LOG_FAULT);

}


void ro_guard_timer_setup(bool init, void* timer_callback) {

    ro_guard_timer.expires    = jiffies + 1*HZ;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
   ro_guard_timer.data       = 1;
   ro_guard_timer.function   = timer_callback;
   init_timer(&ro_guard_timer);
#else
   timer_setup(&ro_guard_timer, timer_callback, 0);
#endif
   add_timer(&ro_guard_timer);

   if (init)
       ro_data_init(&ved_ro_data);

}


void ro_data_check(struct timer_list *timer) {

    ro_guard_timer_setup(false, ro_data_check);
    global_ro_data_check(&ved_ro_data);
    kprobe_check();

}


void ro_guard_timer_init() {

    ro_guard_timer_setup(true, ro_data_check);
    ro_data_init(&ved_ro_data);

}
