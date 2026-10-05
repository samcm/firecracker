/* SPDX-License-Identifier: Apache-2.0 */
/* Frozen v1 integration stub; must match the kernel owner's UAPI before deployment. */
#ifndef FIRECRACKER_MEMVERSION_H
#define FIRECRACKER_MEMVERSION_H
#include <linux/ioctl.h>
#include <linux/types.h>
#define MV_ABI_VERSION 1
struct mv_region { __u64 addr, len; };
struct mv_exclusion { __u32 region, reserved; __u64 offset, len; };
struct mv_create {
    __u64 regions, exclusions;
    __u32 nr_regions, nr_exclusions, flags;
    __s32 fd;
};
#define MV_MAP_PRIVATE 0x1
#define MV_MAP_READ 0x2
struct mv_map { __u32 region, flags; __u64 addr; };
struct mv_info {
    __u32 abi, nr_regions;
    __u64 regions, present_pages, excluded_pages;
    __u64 new_pages;
};
#define MV_IOC_CREATE _IOWR('V', 0x40, struct mv_create)
#define MV_IOC_MAP _IOW('V', 0x41, struct mv_map)
#define MV_IOC_INFO _IOWR('V', 0x42, struct mv_info)
#endif
