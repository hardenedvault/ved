# [VED (Vault Exploit Defense)](https://hardenedvault.net/products/ved) - Linux kernel threat detection and prevention system

## How VED evolved
Our previous [write-up](https://hardenedvault.net/blog/2021-09-06-ved/) introduced the problem and the current status of Linux kernel security and why cloud native and automotive solution should adopt 3rd-party Linux kernel hardening solution. We've been trying to build the full-stack security solution for platform and infrastructure running (GNU)-Linux systems and we learned a lot from [PaX/GRsecurity](https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/kernel_mitigation.md). We continuous study the linux kernel vulnerablity exploit methods disclosured from 2010 to present and see how attacker combined them into the offensive actions, which some cases are public while some are not. Then we began to study how to achieve the trade-off between simplicity of deployment, performance hit, stability and security, which is the starting point of VED's design and implementation. E.g:

* To determine whether the detection scope of some code modules should be reduced based on the commonality of the exploit method

* The VED and Linux kernels are a whole for enterprise production environments, and we also stress-tested the specific versions of Linux kernel subsystems that are highly rely on client's production through VaultFuzzer to achieve high code coverage.

* The security solution plays the role of the guardian of the system, and the VED strengthens its protection ability through the VSPP self-protection feature to avoid the weakness of other Linux kernel solution has, e.g: [Tetragon](https://hardenedvault.net/blog/2022-05-25-vspp/), etc.

Theoretically, the features of VED can be compatible with any LKM framework including [LKRG](https://lkrg.org/), [AKO](https://link.springer.com/content/pdf/10.1007/s10207-020-00514-7.pdf) and even a Linux kernel rootkit. Our LKM implementation is finally selected based on open source and long-term maintenance of [LKRG](https://github.com/lkrg-org/lkrg). We analyzed the vulnerablity exploitation methods from those public exploits, as well as some 0day vulnerablities provided by the clients.

|Vulnerablity | Mitigation stage | 
|:-----------:|:----------------:|
|[CVE-2021-22555](https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html)|  Exploitation   | 
|[CVE-2021-3573](https://f0rm2l1n.github.io/2021-07-23-Blue-Klotski/)| Exploitation |
|[CVE-2021-3490](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story) | Post-exploitation, situational hardening |
|[CVE-2021-33909](https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt)| Exploitation |
|[CVE-2021-34866](https://blog.hexrabbit.io/2021/11/03/CVE-2021-34866-writeup/)| Exploitation |
|[CVE-2021-43267](https://haxx.in/posts/pwning-tipc/)| Exploitation |
|[CVE-2021-42008](https://syst3mfailure.io/sixpack-slab-out-of-bounds)| Exploitation |
|[CVE-2022-0185](https://www.willsroot.io/2022/01/cve-2022-0185.html)| Exploitation |
|[CVE-2022-0492](https://thehackernews.com/2022/03/new-linux-kernel-cgroups-vulnerability.html)| Post-exploitation, situational hardening |
|[ CVE-2022-25636](https://github.com/Bonfee/CVE-2022-25636)| Exploitation |
|[CVE-2022-1015/CVE-2022-1015-1016](https://blog.dbouman.nl/2022/04/02/How-The-Tables-Have-Turned-CVE-2022-1015-1016)| Exploitation |
|[CVE-2022-23222](https://github.com/tr3ee/CVE-2022-23222)| Post-exploitation |
|[Tetragon bypass](https://grsecurity.net/tetragone_a_lesson_in_security_fundamentals)| Exploitation |

We built an AMI on AWS. You can test a few exploits if you want to play. Choose US East (N.Virginia) region and search "vault exploit test" :

![1](https://hardenedvault.net/images/blog/exp-test-ami_hu0203f358a19a712507b357cca5900333_113554_1387x625_fit_q100_h2_box_3.webp)

We also provide Hardened Linux (Ubuntu for both x86_64 and arm64) on AWS and it got a fancy name: [Beyond Compliance](https://hardenedvault.net/saas/). It ships security by default, easily complying with PCI-DSS/GDPR via CIS/STIG benchmark, as well as ModSecurity (Web Application Firewall), VED (Vault Exploit Defense) and more features. 

* [Hardened Linux (Ubuntu 22.04 for x86_64)](https://aws.amazon.com/marketplace/pp/prodview-4nur74fayxeis)
* Hardened Linux (Ubuntu 22.04 for arm64)

![2](https://hardenedvault.net/images/products/ved-bigger-picture_hu967785bdae19a1b195923c538216bb8a_653262_1741x919_fit_q100_h2_box_3.webp)

## Validation type: From Vault's perspective

## LKRG features
1. Checks on SMEP/SMAP disable/enable (p_ed_pcfi_cpu).
2. pCFI(pSMEP/sSPC): stack pointer, size, check if return addresses is kernel .text.
3. Privilege escalation: check if credentials were modified (p_ed_enforce_validation).
4. Kernel text integrity. Modules load checking.
5. addr_limit (old kernel version).
6. hiding LKRG itself.

## VED features
1. wCFI: Check if return address is at right callsite.
2. wCFI: Callees that may be reused can only be called by specified functions  (depend on disabling tail-call optimization and direct call). 
3. VSPP (Vault self-protection): Check if any essential kprobe was disabled.
4. ro guard timer: check if kprobe was globally disarmed.


### New process

kprobe point: `sys_execve,sys_execveat, sys_ptrace, do_wakeup, wake_up_new_task`

Triger point: Start a new process.

Reaction: L1 + L2 + V1 + L3

### May be used in doing privilege escalation

kprobe point: `native_write_cr4, commit_creds, override_creds, revert_creds, call_usermodehelper_exec, call_usermodehelper, set_current_groups， sys_set*id, sys_capset `

Trigger point: These kernel functions may be reused to do privilege  escalation, check if they are called from the available call sites and only update credentials if checks are passed. 

Reaction: L1 + L2 + V1 + L3 + V1

### May be used to bypass LKM security solution

kprobe point: `disable_kprobe, p_exploit_detection_exit, text_poke`

Triger point: These kernel functions may be reused to bypass LKM solution (LKRG, AKO, Tetragon, etc), check if they are called by available call site or right credentails.

Reaction: L1 + L2 + V1 + L3 + V1 + V3

### Post-exploitation checks

kprobe point: `mark_inode_dirty, sys_unshare, cap_task_prctl, sys_add_key, security_ptrace_access, generic_permission, security_bprm_committed_creds, security_bprm_committing_creds, wake_up_new_task, sys_ptrace`

Triger point: After privilege escalation has happened, the exploit may  do something that would trigger capability/credential check. Extra credential checks that may detect exploits are added here.

Reaction: L1 + L2 + V1 + V3

### Timer and schedule

#### LKRG timer

kprobe point: schedule, lookup_fast, __queue_work, wake_up_new_task

Trigger point: Detect exploition more frequently.

Reaction: L1 + L2 + V1 + L3 + L5 + L6 + V3

* Interval: 15 seconds by default

#### VED ro guard

read only data: kptr_restrict, kprobes_all_disarmed

Trigger point: cyclical check if these essential data were corrupted.

Reaction: L4 + V4

* Interval: 1 second

## How to build
`make && insmod ved.ko`
