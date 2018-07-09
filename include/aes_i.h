/*
 * AES (Rijndael) cipher
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_I_H
#define AES_I_H

#include "aes.h"

/* #define FULL_UNROLL */
#define AES_SMALL_TABLES

extern const u32 Te0[256];
extern const u32 Te1[256];
extern const u32 Te2[256];
extern const u32 Te3[256];
extern const u32 Te4[256];
extern const u32 Td0[256];
extern const u32 Td1[256];
extern const u32 Td2[256];
extern const u32 Td3[256];
extern const u32 Td4[256];
extern const u32 rcon[10];
extern const u8 Td4s[256];
extern const u8 rcons[10];

#ifndef AES_SMALL_TABLES

#define RCON(i) rcon[(i)]

#define TE0(i) Te0[((i) >> 24u) & 0xffu]
#define TE1(i) Te1[((i) >> 16u) & 0xffu]
#define TE2(i) Te2[((i) >> 8u) & 0xffu]
#define TE3(i) Te3[(i)&0xffu]
#define TE41(i) (Te4[((i) >> 24u) & 0xffu] & 0xff000000u)
#define TE42(i) (Te4[((i) >> 16u) & 0xffu] & 0x00ff0000u)
#define TE43(i) (Te4[((i) >> 8u) & 0xffu] & 0x0000ff00u)
#define TE44(i) (Te4[(i)&0xffu] & 0x000000ffu)
#define TE421(i) (Te4[((i) >> 16u) & 0xffu] & 0xff000000u)
#define TE432(i) (Te4[((i) >> 8u) & 0xffu] & 0x00ff0000u)
#define TE443(i) (Te4[(i)&0xffu] & 0x0000ff00u)
#define TE414(i) (Te4[((i) >> 24u) & 0xffu] & 0x000000ffu)
#define TE411(i) (Te4[((i) >> 24u) & 0xffu] & 0xff000000u)
#define TE422(i) (Te4[((i) >> 16u) & 0xffu] & 0x00ff0000u)
#define TE433(i) (Te4[((i) >> 8u) & 0xffu] & 0x0000ff00u)
#define TE444(i) (Te4[(i)&0xffu] & 0x000000ffu)
#define TE4(i) (Te4[(i)] & 0x000000ffu)

#define TD0(i) Td0[((i) >> 24u) & 0xffu]
#define TD1(i) Td1[((i) >> 16u) & 0xffu]
#define TD2(i) Td2[((i) >> 8u) & 0xffu]
#define TD3(i) Td3[(i)&0xffu]
#define TD41(i) (Td4[((i) >> 24u) & 0xffu] & 0xff000000u)
#define TD42(i) (Td4[((i) >> 16u) & 0xffu] & 0x00ff0000u)
#define TD43(i) (Td4[((i) >> 8u) & 0xffu] & 0x0000ff00u)
#define TD44(i) (Td4[(i)&0xffu] & 0x000000ffu)
#define TD0_(i) Td0[(i)&0xffu]
#define TD1_(i) Td1[(i)&0xffu]
#define TD2_(i) Td2[(i)&0xffu]
#define TD3_(i) Td3[(i)&0xffu]

#else /* AES_SMALL_TABLES */

#define RCON(i) (rcons[(i)] << 24u)

static inline u32 rotr(u32 val, int bits) {
  return (val >> bits) | (val << (32 - bits));
}

#define TE0(i) Te0[((i) >> 24u) & 0xffu]
#define TE1(i) rotr(Te0[((i) >> 16u) & 0xffu], 8)
#define TE2(i) rotr(Te0[((i) >> 8u) & 0xffu], 16)
#define TE3(i) rotr(Te0[(i)&0xffu], 24)
#define TE41(i) ((Te0[((i) >> 24u) & 0xffu] << 8u) & 0xff000000u)
#define TE42(i) (Te0[((i) >> 16u) & 0xffu] & 0x00ff0000u)
#define TE43(i) (Te0[((i) >> 8u) & 0xffu] & 0x0000ff00u)
#define TE44(i) ((Te0[(i)&0xffu] >> 8u) & 0x000000ffu)
#define TE421(i) ((Te0[((i) >> 16u) & 0xffu] << 8u) & 0xff000000u)
#define TE432(i) (Te0[((i) >> 8u) & 0xffu] & 0x00ff0000u)
#define TE443(i) (Te0[(i)&0xffu] & 0x0000ff00u)
#define TE414(i) ((Te0[((i) >> 24u) & 0xffu] >> 8u) & 0x000000ffu)
#define TE411(i) ((Te0[((i) >> 24u) & 0xffu] << 8u) & 0xff000000u)
#define TE422(i) (Te0[((i) >> 16u) & 0xffu] & 0x00ff0000u)
#define TE433(i) (Te0[((i) >> 8u) & 0xffu] & 0x0000ff00u)
#define TE444(i) ((Te0[(i)&0xffu] >> 8u) & 0x000000ffu)
#define TE4(i) ((Te0[(i)] >> 8u) & 0x000000ffu)

#define TD0(i) Td0[((i) >> 24u) & 0xffu]
#define TD1(i) rotr(Td0[((i) >> 16u) & 0xffu], 8u)
#define TD2(i) rotr(Td0[((i) >> 8u) & 0xffu], 16u)
#define TD3(i) rotr(Td0[(i)&0xffu], 24u)
#define TD41(i) (Td4s[((i) >> 24u) & 0xffu] << 24u)
#define TD42(i) (Td4s[((i) >> 16u) & 0xffu] << 16u)
#define TD43(i) (Td4s[((i) >> 8u) & 0xffu] << 8u)
#define TD44(i) (Td4s[(i)&0xffu])
#define TD0_(i) Td0[(i)&0xffu]
#define TD1_(i) rotr(Td0[(i)&0xffu], 8)
#define TD2_(i) rotr(Td0[(i)&0xffu], 16)
#define TD3_(i) rotr(Td0[(i)&0xffu], 24)

#endif /* AES_SMALL_TABLES */

#ifdef _MSC_VER
#define SWAP(x) (_lrotl(x, 8) & 0x00ff00ff | _lrotr(x, 8) & 0xff00ff00)
#define GETU32(p) SWAP(*((u32 *)(p)))
#define PUTU32(ct, st)                                                         \
  { *((u32 *)(ct)) = SWAP((st)); }
#else
#define GETU32(pt)                                                             \
  (((u32)(pt)[0] << 24u) ^ ((u32)(pt)[1] << 16u) ^ ((u32)(pt)[2] << 8u) ^      \
   ((u32)(pt)[3]))
#define PUTU32(ct, st)                                                         \
  {                                                                            \
    (ct)[0] = (u8)((st) >> 24u);                                               \
    (ct)[1] = (u8)((st) >> 16u);                                               \
    (ct)[2] = (u8)((st) >> 8u);                                                \
    (ct)[3] = (u8)(st);                                                        \
  }
#endif

#define AES_PRIV_SIZE (4 * 4 * 15 + 4)
#define AES_PRIV_NR_POS (4 * 15)

int rijndaelKeySetupEnc(u32 rk[], const u8 cipherKey[], int keyBits);

#endif /* AES_I_H */
