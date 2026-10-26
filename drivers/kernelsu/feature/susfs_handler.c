// SPDX-License-Identifier: GPL-2.0-only
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/susfs.h>

#define KERNEL_SU_OPTION 0xDEADBEEF

#define CMD_SUSFS_ADD_SUS_PATH 0x55550
#define CMD_SUSFS_ADD_SUS_MOUNT 0x55560
#define CMD_SUSFS_ADD_SUS_KSTAT 0x55570
#define CMD_SUSFS_UPDATE_SUS_KSTAT 0x55571
#define CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY 0x55572
#define CMD_SUSFS_ADD_TRY_UMOUNT 0x55580
#define CMD_SUSFS_SET_UNAME 0x55590
#define CMD_SUSFS_ENABLE_LOG 0x555a0
#define CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define CMD_SUSFS_ADD_OPEN_REDIRECT 0x555c0
#define CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS 0x555d0
#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define CMD_SUSFS_SHOW_ENABLED_FEATURES 0x555e2
#define CMD_SUSFS_SHOW_VARIANT 0x555e3

#define DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS "/data/adb/susfs_umount_for_zygote_system_process"
#define DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT "/data/adb/susfs_no_auto_add_sus_bind_mount"
#define DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT "/data/adb/susfs_no_auto_add_sus_ksu_default_mount"
#define DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT "/data/adb/susfs_no_auto_add_try_umount_for_bind_mount"

#include "manager/manager_identity.h"
#include "policy/allowlist.h"
#include "feature/susfs_handler.h"

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
bool susfs_is_umount_for_zygote_system_process_enabled = false;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
extern bool susfs_is_auto_add_sus_bind_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
extern bool susfs_is_auto_add_sus_ksu_default_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
extern bool susfs_is_auto_add_try_umount_for_bind_mount_enabled;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_run_try_umount_for_current_mnt_ns(void);
#endif

static inline int ksu_access_ok(const void __user *addr, unsigned long size)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	return access_ok(VERIFY_READ, addr, size);
#else
	return access_ok(addr, size);
#endif
}

void susfs_on_post_fs_data(void)
{
	struct path path;
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (!kern_path(DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS, 0, &path)) {
		susfs_is_umount_for_zygote_system_process_enabled = true;
		path_put(&path);
	}
	pr_info("susfs_is_umount_for_zygote_system_process_enabled: %d\n", susfs_is_umount_for_zygote_system_process_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_bind_mount_enabled: %d\n", susfs_is_auto_add_sus_bind_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, 0, &path)) {
		susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_sus_ksu_default_mount_enabled: %d\n", susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
	if (!kern_path(DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, 0, &path)) {
		susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
		path_put(&path);
	}
	pr_info("susfs_is_auto_add_try_umount_for_bind_mount_enabled: %d\n", susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif
}

bool susfs_is_allow_su(void)
{
	if (is_manager())
		return true;
	return ksu_is_allow_uid(current_uid().val);
}

int susfs_handle_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	if (option != KERNEL_SU_OPTION)
		return -EINVAL;

	if (current_uid().val != 0)
		return -EPERM;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	if (arg2 == CMD_SUSFS_ADD_SUS_PATH) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_path))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_add_sus_path((struct st_susfs_sus_path __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (arg2 == CMD_SUSFS_ADD_SUS_MOUNT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_mount))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_UPDATE_SUS_KSTAT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	if (arg2 == CMD_SUSFS_ADD_TRY_UMOUNT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_try_umount))) {
			pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_add_try_umount((struct st_susfs_try_umount __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS) {
		susfs_run_try_umount_for_current_mnt_ns();
		pr_info("susfs: CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS -> done\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (arg2 == CMD_SUSFS_SET_UNAME) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_uname))) {
			pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_set_uname((struct st_susfs_uname __user *)arg3);
		pr_info("susfs: CMD_SUSFS_SET_UNAME -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	if (arg2 == CMD_SUSFS_ENABLE_LOG) {
		int error = 0;
		if (arg3 != 0 && arg3 != 1) {
			pr_err("susfs: CMD_SUSFS_ENABLE_LOG -> arg3 can only be 0 or 1\n");
			return 0;
		}
		susfs_set_log((bool)arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (arg2 == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)) {
			pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_set_cmdline_or_bootconfig((char __user *)arg3);
		pr_info("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	if (arg2 == CMD_SUSFS_ADD_OPEN_REDIRECT) {
		int error = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_open_redirect))) {
			pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg5 is not accessible\n");
			return 0;
		}
		error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

	if (arg2 == CMD_SUSFS_SHOW_VERSION) {
		int error = 0;
		int len_of_susfs_version = strlen(SUSFS_VERSION);
		char *susfs_version = SUSFS_VERSION;
		if (!ksu_access_ok((void __user *)arg3, len_of_susfs_version + 1)) {
			pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg5 is not accessible\n");
			return 0;
		}
		error = copy_to_user((void __user *)arg3, (void *)susfs_version, len_of_susfs_version + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}

	if (arg2 == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
		int error = 0;
		u64 enabled_features = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(u64))) {
			pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg5 is not accessible\n");
			return 0;
		}
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		enabled_features |= (1 << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		enabled_features |= (1 << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
		enabled_features |= (1 << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
		enabled_features |= (1 << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		enabled_features |= (1 << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
		enabled_features |= (1 << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		enabled_features |= (1 << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
		enabled_features |= (1 << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		enabled_features |= (1 << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		enabled_features |= (1 << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		enabled_features |= (1 << 10);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		enabled_features |= (1 << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		enabled_features |= (1 << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		enabled_features |= (1 << 14);
#endif
		error = copy_to_user((void __user *)arg3, (void *)&enabled_features, sizeof(enabled_features));
		pr_info("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}

	if (arg2 == CMD_SUSFS_SHOW_VARIANT) {
		int error = 0;
		int len_of_variant = strlen(SUSFS_VARIANT);
		char *susfs_variant = SUSFS_VARIANT;
		if (!ksu_access_ok((void __user *)arg3, len_of_variant + 1)) {
			pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg3 is not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg5 is not accessible\n");
			return 0;
		}
		error = copy_to_user((void __user *)arg3, (void *)susfs_variant, len_of_variant + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}

	return -EINVAL;
}

int susfs_handle_reboot(unsigned int cmd, void __user *arg)
{
	if (current_uid().val != 0)
		return -EPERM;

	switch (cmd) {
	case CMD_SUSFS_SHOW_VERSION: {
		struct {
			char version[SUSFS_MAX_VERSION_BUFSIZE];
			int err;
		} info;
		memset(&info, 0, sizeof(info));
		strncpy(info.version, SUSFS_VERSION, sizeof(info.version) - 1);
		info.err = 0;
		if (copy_to_user(arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	case CMD_SUSFS_SHOW_VARIANT: {
		struct {
			char variant[SUSFS_MAX_VARIANT_BUFSIZE];
			int err;
		} info;
		memset(&info, 0, sizeof(info));
		strncpy(info.variant, SUSFS_VARIANT, sizeof(info.variant) - 1);
		info.err = 0;
		if (copy_to_user(arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	case CMD_SUSFS_SHOW_ENABLED_FEATURES: {
		struct {
			char enabled_features[8192];
			int err;
		} *info;
		info = kzalloc(sizeof(*info), GFP_KERNEL);
		if (!info)
			return -ENOMEM;
		snprintf(info->enabled_features, sizeof(info->enabled_features),
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
			"CONFIG_KSU_SUSFS_SUS_PATH\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
			"CONFIG_KSU_SUSFS_SUS_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
			"CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
			"CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
			"CONFIG_KSU_SUSFS_SUS_KSTAT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
			"CONFIG_KSU_SUSFS_SUS_OVERLAYFS\n"
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
			"CONFIG_KSU_SUSFS_TRY_UMOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
			"CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
			"CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
			"CONFIG_KSU_SUSFS_ENABLE_LOG\n"
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
			"CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
			"CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
			"CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
			"CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT\n"
#endif
			);
		info->err = 0;
		if (copy_to_user(arg, info, sizeof(*info))) {
			kfree(info);
			return -EFAULT;
		}
		kfree(info);
		return 0;
	}
	case CMD_SUSFS_ENABLE_LOG: {
		struct {
			bool enabled;
			int err;
		} info;
		if (copy_from_user(&info, arg, sizeof(info)))
			return -EFAULT;
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		susfs_set_log(info.enabled);
		info.err = 0;
#else
		info.err = 126;
#endif
		if (copy_to_user(arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	case CMD_SUSFS_SET_UNAME: {
		struct {
			char release[65];
			char version[65];
			int err;
		} info;
		if (copy_from_user(&info, arg, sizeof(info)))
			return -EFAULT;
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		info.err = susfs_set_uname_kernel(info.release, info.version);
#else
		info.err = 126;
#endif
		if (copy_to_user(arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
	}
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: {
		struct {
			char fake_cmdline[SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
			int err;
		} *info;
		info = kmalloc(sizeof(*info), GFP_KERNEL);
		if (!info)
			return -ENOMEM;
		if (copy_from_user(info, arg, sizeof(*info))) {
			kfree(info);
			return -EFAULT;
		}
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		info->err = susfs_set_cmdline_or_bootconfig_kernel(info->fake_cmdline);
#else
		info->err = 126;
#endif
		if (copy_to_user(arg, info, sizeof(*info))) {
			kfree(info);
			return -EFAULT;
		}
		kfree(info);
		return 0;
	}
	case CMD_SUSFS_ADD_SUS_PATH:
	case CMD_SUSFS_ADD_SUS_PATH_LOOP: {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		struct {
			char target_pathname[SUSFS_MAX_LEN_PATHNAME];
			int err;
		} info;
		struct st_susfs_sus_path kinfo;
		if (copy_from_user(&info, arg, sizeof(info)))
			return -EFAULT;
		memset(&kinfo, 0, sizeof(kinfo));
		strncpy(kinfo.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
		info.err = susfs_add_sus_path_kernel(&kinfo);
		if (copy_to_user(arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
#else
		return -EOPNOTSUPP;
#endif
	}
	case CMD_SUSFS_ADD_OPEN_REDIRECT: {
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		struct {
			char target_pathname[SUSFS_MAX_LEN_PATHNAME];
			char redirected_pathname[SUSFS_MAX_LEN_PATHNAME];
			int uid_scheme;
			int err;
		} info;
		struct st_susfs_open_redirect kinfo;
		if (copy_from_user(&info, arg, sizeof(info)))
			return -EFAULT;
		memset(&kinfo, 0, sizeof(kinfo));
		strncpy(kinfo.target_pathname, info.target_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
		strncpy(kinfo.redirected_pathname, info.redirected_pathname, SUSFS_MAX_LEN_PATHNAME - 1);
		info.err = susfs_add_open_redirect_kernel(&kinfo);
		if (copy_to_user(arg, &info, sizeof(info)))
			return -EFAULT;
		return 0;
#else
		return -EOPNOTSUPP;
#endif
	}
	default:
		return -EINVAL;
	}
}
