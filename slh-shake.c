/* slh-shake.c

   Copyright (C) 2025 Niels Möller

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

#include "slh-dsa-internal.h"

#include "bswap-internal.h"
#include "sha3.h"

/* Fields always big-endian */
struct slh_address_tree
{
  uint32_t layer;
  uint32_t pad; /* Always zero */
  uint64_t tree_idx;
};

void
_slh_shake_init (struct sha3_ctx *ctx, const uint8_t *public_seed,
		 uint32_t layer, uint64_t tree_idx)
{
  struct slh_address_tree at = { bswap32_if_le (layer), 0, bswap64_if_le (tree_idx) };

  sha3_init (ctx);
  sha3_256_update (ctx, _SLH_DSA_128_SIZE, public_seed);
  sha3_256_update (ctx, sizeof (at), (const uint8_t *) &at);
}

void
_slh_shake (const struct sha3_ctx *tree_ctx, const struct slh_address_hash *ah,
	    const uint8_t *secret, uint8_t *out)
{
  struct sha3_ctx ctx = *tree_ctx;
  sha3_256_update (&ctx, sizeof (*ah), (const uint8_t *) ah);
  sha3_256_update (&ctx, _SLH_DSA_128_SIZE, secret);
  sha3_256_shake (&ctx, _SLH_DSA_128_SIZE, out);
}
