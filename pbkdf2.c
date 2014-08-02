// gcc -c -I/usr/local/include/urweb pbkdf2.c

#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <urweb.h>

#include "pbkdf2.h"

uw_Basis_blob *uw_Pbkdf2_pkcs5_pbkdf2_hmac_sha1(uw_context ctx, uw_Basis_int size, uw_Basis_int iter, uw_Basis_string str, uw_Basis_string salt) {
  uw_Basis_blob *b;
  int ret;
  
  b = uw_malloc(ctx, sizeof(uw_Basis_blob));
  
  b->size = size;
  b->data = uw_malloc(ctx, b->size);
  
  ret = PKCS5_PBKDF2_HMAC_SHA1(str, strlen(str),
                               salt, strlen(salt),
                               iter,
                               b->size, b->data);
  
  if(!ret) return NULL;
  
  return b;
}

uw_Basis_bool uw_Pbkdf2_eq(uw_context ctx, uw_Basis_blob b1, uw_Basis_blob b2) {
  int i;
  int result = 0;

  if(b1.size != b2.size) return 0;
  
  for(i = 0; i < b1.size; i++) {
    result |= b1.data[i] ^ b2.data[i];
  }
  
  return result ? uw_Basis_False : uw_Basis_True;
}

// http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06
uw_Basis_blob uw_Pbkdf2_test_vector(uw_context ctx, uw_Basis_int i) {
  char *data;
  uw_Basis_blob b;
  
  // P = "password" (8 octets)
  // S = "salt" (4 octets)
  // c = 1
  // dkLen = 20
  char t0[] = {0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
               0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
               0x2f, 0xe0, 0x37, 0xa6};
  
  // P = "password" (8 octets)
  // S = "salt" (4 octets)
  // c = 2
  // dkLen = 20
  char t1[] = {0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
               0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
               0xd8, 0xde, 0x89, 0x57};
  
  // P = "password" (8 octets)
  // S = "salt" (4 octets)
  // c = 4096
  // dkLen = 20
  char t2[] = {0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
               0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
               0x65, 0xa4, 0x29, 0xc1};

  // P = "password" (8 octets)
  // S = "salt" (4 octets)
  // c = 16777216
  // dkLen = 20
  char t3[] = {0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
               0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
               0x26, 0x34, 0xe9, 0x84};

  // P = "passwordPASSWORDpassword" (24 octets)
  // S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
  // c = 4096
  // dkLen = 25
  char t4[] = {0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
               0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
               0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
               0x38};
  
  b.size = 0;
  
  switch(i) {
  case 0:
    data = t0;
    b.size = sizeof(t0);
    break;
  case 1:
    data = t1;
    b.size = sizeof(t1);
    break;
  case 2:
    data = t2;
    b.size = sizeof(t2);
    break;
  case 3:
    data = t3;
    b.size = sizeof(t3);
    break;
  case 4:
    data = t4;
    b.size = sizeof(t4);
    break;
  }
  
  b.data = uw_malloc(ctx, b.size);
  memcpy(b.data, data, b.size);
  
  return b;
}
