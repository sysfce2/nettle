/* ml-kem.c

   The ML-KEM (Kyber) key encapsulation mechanism, FIPS 203

   Copyright (C) 2024 Red Hat, Inc.

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "ml-kem.h"

#include "memops.h"
#include "ml-kem-internal.h"
#include "sha3.h"
#include <string.h>

static inline void
H (struct sha3_ctx *ctx,
   size_t len,
   const uint8_t *msg,
   uint8_t *dst)
{
  sha3_init (ctx);
  sha3_256_update (ctx, len, msg);
  sha3_256_digest (ctx, dst);
}

static inline void
G2 (struct sha3_ctx *ctx,
    size_t len1, const uint8_t *msg1,
    size_t len2, const uint8_t *msg2,
    uint8_t *dst)
{
  sha3_init (ctx);
  sha3_512_update (ctx, len1, msg1);
  sha3_512_update (ctx, len2, msg2);
  sha3_512_digest (ctx, dst);
}

static inline void
J2 (struct sha3_ctx *ctx,
    size_t len1, const uint8_t *msg1,
    size_t len2, const uint8_t *msg2,
    uint8_t *dst)
{
  sha3_init (ctx);
  sha3_256_update (ctx, len1, msg1);
  sha3_256_update (ctx, len2, msg2);
  sha3_256_shake (ctx, 32, dst);
}

#define MAX(a, b) ((a) >= (b) ? (a) : (b))

size_t
ml_kem_generate_keypair_itch (const struct ml_kem_params *params)
{
  return _ml_kem_inner_generate_keypair_itch (params);
}

void
ml_kem_generate_keypair (const struct ml_kem_params *params,
			 uint8_t *pub,
			 uint8_t *key,
			 const uint8_t *seed,
			 uint16_t *scratch)
{
  struct sha3_ctx hctx;
  uint8_t *p;

  _ml_kem_inner_generate_keypair (params, pub, key, seed, scratch);

  /* dk = dk|ek|H(ek)|z */
  p = &key[params->inner_private_key_size];
  memcpy (p, pub, params->inner_public_key_size);
  p += params->inner_public_key_size;

  H (&hctx, params->inner_public_key_size, pub, p);
  p += 32;

  memcpy (p, &seed[32], 32);
}

size_t
ml_kem_encap_itch (const struct ml_kem_params *params)
{
  return _ml_kem_inner_encrypt_itch (params);
}

void
ml_kem_encap (const struct ml_kem_params *params,
	      const uint8_t *pub,
	      uint8_t *secret, uint8_t *ciphertext,
	      void *random_ctx, nettle_random_func *random,
	      uint16_t *scratch)
{
  uint8_t m[32], buffer[64], *r = &buffer[32];
  struct sha3_ctx hctx;
  struct sha3_ctx gctx;

  random (random_ctx, sizeof(m), m);

  H (&hctx, params->public_key_size, pub, buffer);
  G2 (&gctx, sizeof(m), m, 32, buffer, buffer);

  _ml_kem_inner_encrypt (params, pub, m, r, ciphertext, scratch);

  memcpy (secret, buffer, 32);
}

size_t
ml_kem_decap_itch (const struct ml_kem_params *params)
{
  /* The scratch space consists of two parts: the first part is used
     for encrypt/decrypt and the second part
     is used for a new ciphertext (for implicit rejection).

     This makes use of the fact that:
     - _ml_kem_inner_encrypt_itch is larger than
     _ml_kem_inner_decrypt_itch
     - params->ciphertext_size is multiple of 32-byte blocks and
     therefore no alignment violation
  */
  return _ml_kem_inner_encrypt_itch (params) + params->ciphertext_size;
}

void
ml_kem_decap (const struct ml_kem_params *params,
	      const uint8_t *key,
	      uint8_t *secret,
	      const uint8_t *ciphertext,
	      uint16_t *scratch)
{
  uint8_t m[32], buffer[64], k2[32];
  const uint8_t *pub = key + params->inner_private_key_size;
  const uint8_t *h = pub + params->inner_public_key_size;
  const uint8_t *z = h + 32;
  struct sha3_ctx hctx;
  struct sha3_ctx gctx;
  volatile int ok = 1;
  uint8_t *ciphertext2 = (uint8_t *)(scratch + _ml_kem_inner_encrypt_itch (params));

  _ml_kem_inner_decrypt (params, key, ciphertext, m, scratch);

  G2 (&gctx, sizeof(m), m, 32, h, buffer);

  _ml_kem_inner_encrypt (params, pub, m, &buffer[32], ciphertext2, scratch);

  /* K1 = KBar2 */
  memcpy (secret, buffer, 32);

  /* K2 = J(z || cipherText) */
  J2 (&hctx, 32, z, params->ciphertext_size, ciphertext, k2);

  ok &= memeql_sec (ciphertext, ciphertext2, params->ciphertext_size);

  cnd_memcpy (!ok, secret, k2, 32);
}
