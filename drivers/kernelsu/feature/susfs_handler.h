/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KSU_H_SUSFS_HANDLER
#define __KSU_H_SUSFS_HANDLER

#ifdef CONFIG_KSU_SUSFS
void susfs_on_post_fs_data(void);
bool susfs_is_allow_su(void);
int susfs_handle_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
int susfs_handle_reboot(unsigned int cmd, void __user *arg);
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern bool susfs_is_umount_for_zygote_system_process_enabled;
#endif
#else
static inline void susfs_on_post_fs_data(void) {}
static inline int susfs_handle_reboot(unsigned int cmd, void __user *arg) { return -EOPNOTSUPP; }
#endif

#endif /* __KSU_H_SUSFS_HANDLER */
