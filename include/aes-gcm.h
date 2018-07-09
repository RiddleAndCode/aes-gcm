#ifndef AES_GCM_H
#define AES_GCM_H

#include "common.h"
#include "includes.h"

#include "aes.h"
#include "aes_i.h"

int aes_gcm_ae(const u8 *key, size_t key_len, const u8 *iv, size_t iv_len,
               const u8 *plain, size_t plain_len, const u8 *aad, size_t aad_len,
               u8 *crypt, u8 *tag);
int aes_gcm_ad(const u8 *key, size_t key_len, const u8 *iv, size_t iv_len,
               const u8 *crypt, size_t crypt_len, const u8 *aad, size_t aad_len,
               const u8 *tag, u8 *plain);
int aes_gmac(const u8 *key, size_t key_len, const u8 *iv, size_t iv_len,
             const u8 *aad, size_t aad_len, u8 *tag);

#endif /* AES_GCM_H */