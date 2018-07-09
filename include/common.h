/*
 * wpa_supplicant/hostapd / common helper functions, etc.
 * Copyright (c) 2002-2007, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t
#define AES_BLOCK_SIZE 16
#define os_memcmp_const memcmp
#define os_memcmp memcmp
#define os_memcpy memcpy
#define os_memset memset
#define os_strlen strlen

// common.h
#define BIT(x) (1u << (x))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static inline void WPA_PUT_BE64(u8 *a, u64 val) {
  a[0] = val >> 56;
  a[1] = val >> 48;
  a[2] = val >> 40;
  a[3] = val >> 32;
  a[4] = val >> 24;
  a[5] = val >> 16;
  a[6] = val >> 8;
  a[7] = val & 0xff;
}

static inline u32 WPA_GET_BE32(const u8 *a) {
  return ((u32)a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void WPA_PUT_BE32(u8 *a, u32 val) {
  a[0] = (val >> 24) & 0xff;
  a[1] = (val >> 16) & 0xff;
  a[2] = (val >> 8) & 0xff;
  a[3] = val & 0xff;
}

// aes-gcm.c
#endif /* COMMON_H */
