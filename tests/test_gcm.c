/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */


#include "tests.h"

/*
 * GCM test vectors from
 * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 */
struct gcm_test_vector {
  char *k;
  char *p;
  char *aad;
  char *iv;
  char *c;
  char *t;
};

static int hex2num(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

static int hex2byte(const char *hex) {
  int a, b;
  a = hex2num(*hex++);
  if (a < 0) {
    return -1;
  }
  b = hex2num(*hex++);
  if (b < 0) {
    return -1;
  }
  return ((uint32_t)a << 4u) | (uint32_t)b;
}

static int hexstr2bin(const char *hex, u8 *buf, size_t len) {
  size_t i;
  const char *ipos = hex;
  u8 *opos = buf;

  for (i = 0; i < len; i++) {
    int a = hex2byte(ipos);
    if (a < 0) {
      return -1;
    }
    *opos++ = a;
    ipos += 2;
  }
  return 0;
}

static const struct gcm_test_vector gcm_tests[] = {
  {
    /* Test Case 1 */
    "00000000000000000000000000000000", "", "", "000000000000000000000000", "",
    "58e2fccefa7e3061367f1d57a4e7455a"
  },
  {
    /* Test Case 2 */
    "00000000000000000000000000000000", "00000000000000000000000000000000", "",
    "000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78",
    "ab6e47d42cec13bdf53a67b21257bddf"
  },
  {
    /* Test Case 3 */
    "feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    "", "cafebabefacedbaddecaf888",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25"
    "466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
    "4d5c2af327cd64a62cf35abd2ba6fab4"
  },
  {
    /* Test Case 4 */
    "feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbaddecaf888",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25"
    "466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
    "5bc94fbc3221a5db94fae95ae7121a47"
  },
  {
    /* Test Case 5 */
    "feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbad",
    "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e"
    "49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
    "3612d2e79e3b0785561be14aaca2fccb"
  },
  {
    /* Test Case 6 */
    "feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c9515"
    "6809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
    "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4f"
    "ba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
    "619cc5aefffe0bfa462af43c1699d050"
  },
  {
    /* Test Case 7 */
    "000000000000000000000000000000000000000000000000", "", "",
    "000000000000000000000000", "", "cd33b28ac773f74ba00ed1f312572435"
  },
  {
    /* Test Case 8 */
    "000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000", "", "000000000000000000000000",
    "98e7247c07f0fe411c267e4384b0f600", "2ff58d80033927ab8ef4d4587514f0fb"
  },
  {
    /* Test Case 9 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    "", "cafebabefacedbaddecaf888",
    "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c"
    "144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
    "9924a7c8587336bfb118024db8674a14"
  },
  {
    /* Test Case 10 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbaddecaf888",
    "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c"
    "144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
    "2519498e80f1478f37ba55bd6d27618c"
  },
  {
    /* Test Case 11 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbad",
    "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057fddc29df9"
    "a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
    "65dcc57fcf623a24094fcca40d3533f8"
  },
  {
    /* Test Case 12 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c9515"
    "6809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
    "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e4581e79012a"
    "f34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
    "dcf566ff291c25bbb8568fc3d376a6d9"
  },
  {
    /* Test Case 13 */
    "0000000000000000000000000000000000000000000000000000000000000000", "", "",
    "000000000000000000000000", "", "530f8afbc74536b9a963b4f1c4cb738b"
  },
  {
    /* Test Case 14 */
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000", "", "000000000000000000000000",
    "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"
  },
  {
    /* Test Case 15 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    "", "cafebabefacedbaddecaf888",
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e485"
    "90dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
    "b094dac5d93471bdec1a502270e3cc6c"
  },
  {
    /* Test Case 16 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbaddecaf888",
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e485"
    "90dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
    "76fc6ece0f4e1768cddf8853bb2d551b"
  },
  {
    /* Test Case 17 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2", "cafebabefacedbad",
    "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0feb582d33"
    "934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
    "3a337dbf46a792c45e454913fe2ea8f2"
  },
  {
    /* Test Case 18 */
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c959"
    "56809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c9515"
    "6809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
    "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b78"
    "0f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
    "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"
  }
};

void test_gcm(void) {
  int ret = 0;
  uint32_t i;
  u8 k[32], aad[32], iv[64], t[16], tag[16];
  u8 p[64], c[64], tmp[64];
  size_t p_len, aad_len, iv_len;

  for (i = 0; i < ARRAY_SIZE(gcm_tests); i++) {
    const struct gcm_test_vector *tc = &gcm_tests[i];

    size_t k_len = os_strlen(tc->k) / 2;
    if (hexstr2bin(tc->k, k, k_len)) {
      printf("Invalid GCM test vector %u (k)\n", i);
      ret++;
      continue;
    }

    p_len = os_strlen(tc->p) / 2;
    if (hexstr2bin(tc->p, p, p_len)) {
      printf("Invalid GCM test vector %u (p)\n", i);
      ret++;
      continue;
    }

    aad_len = os_strlen(tc->aad) / 2;
    if (hexstr2bin(tc->aad, aad, aad_len)) {
      printf("Invalid GCM test vector %u (aad)\n", i);
      ret++;
      continue;
    }

    iv_len = os_strlen(tc->iv) / 2;
    if (hexstr2bin(tc->iv, iv, iv_len)) {
      printf("Invalid GCM test vector %u (iv)\n", i);
      ret++;
      continue;
    }

    if (hexstr2bin(tc->c, c, p_len)) {
      printf("Invalid GCM test vector %u (c)\n", i);
      ret++;
      continue;
    }

    if (hexstr2bin(tc->t, t, sizeof(t))) {
      printf("Invalid GCM test vector %u (t)\n", i);
      ret++;
      continue;
    }

    if (aes_gcm_ae(k, k_len, iv, iv_len, p, p_len, aad, aad_len, tmp, tag) <
        0) {
      printf("GCM-AE failed (test case %u)\n", i);
      ret++;
      continue;
    }

    if (os_memcmp(c, tmp, p_len) != 0) {
      printf("GCM-AE mismatch (test case %u)\n", i);
      ret++;
    }

    if (os_memcmp(tag, t, sizeof(tag)) != 0) {
      printf("GCM-AE tag mismatch (test case %u)\n", i);
      ret++;
    }

    if (p_len == 0) {
      if (aes_gmac(k, k_len, iv, iv_len, aad, aad_len, tag) < 0) {
        printf("GMAC failed (test case %u)\n", i);
        ret++;
        continue;
      }

      if (os_memcmp(tag, t, sizeof(tag)) != 0) {
        printf("GMAC tag mismatch (test case %u)\n", i);
        ret++;
      }
    }

    if (aes_gcm_ad(k, k_len, iv, iv_len, c, p_len, aad, aad_len, t, tmp) < 0) {
      printf("GCM-AD failed (test case %u)\n", i);
      ret++;
      continue;
    }

    if (os_memcmp(p, tmp, p_len) != 0) {
      printf("GCM-AD mismatch (test case %u)\n", i);
      ret++;
    }
  }
  TEST_ASSERT_EQUAL_INT(0, ret);
}


int main(void) {

  UNITY_BEGIN();
  RUN_TEST(test_gcm);
  return UNITY_END();
}
