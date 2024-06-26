/* ecc-ecdsa-verify.c

   Copyright (C) 2013, 2014 Niels Möller

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

/* Development of Nettle's ECC support was funded by the .SE Internet Fund. */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include "ecdsa.h"
#include "ecc-internal.h"
#include "dsa-internal.h"

/* Low-level ECDSA verify */

static int
ecdsa_in_range (const struct ecc_curve *ecc, const mp_limb_t *xp)
{
  return !mpn_zero_p (xp, ecc->p.size)
    && mpn_cmp (xp, ecc->q.m, ecc->p.size) < 0;
}

mp_size_t
ecc_ecdsa_verify_itch (const struct ecc_curve *ecc)
{
  /* Largest storage need is for the ecc_mul_a call. */
  return 5*ecc->p.size + ECC_MUL_A_ITCH (ecc->p.size);
}

/* FIXME: Use faster primitives, not requiring side-channel silence. */
int
ecc_ecdsa_verify (const struct ecc_curve *ecc,
		  const mp_limb_t *pp, /* Public key */
		  size_t length, const uint8_t *digest,
		  const mp_limb_t *rp, const mp_limb_t *sp,
		  mp_limb_t *scratch)
{
  /* Procedure, according to RFC 6090, "KT-I". q denotes the group
     order.

     1. Check 0 < r, s < q.

     2. s' <-- s^{-1}  (mod q)

     3. u1  <-- h * s' (mod q)

     4. u2  <-- r * s' (mod q)

     5. R = u1 G + u2 Y

     6. Signature is valid if R_x = r (mod q).
  */

#define P2 scratch
#define u1 (scratch + 3*ecc->p.size)
#define u2 (scratch + 4*ecc->p.size)

#define P1 (scratch + 4*ecc->p.size)
#define sinv (scratch)
#define hp (scratch + ecc->p.size)

  if (! (ecdsa_in_range (ecc, rp)
	 && ecdsa_in_range (ecc, sp)))
    return 0;

  /* FIXME: Micro optimizations: Either simultaneous multiplication.
     Or convert to projective coordinates (can be done without
     division, I think), and write an ecc_add_ppp. */

  /* Compute sinv */
  ecc->q.invert (&ecc->q, sinv, sp, sinv + ecc->p.size);

  /* u1 = h / s, P1 = u1 * G */
  _nettle_dsa_hash (hp, ecc->q.bit_size, length, digest);
  ecc_mod_mul_canonical (&ecc->q, u1, hp, sinv, u1);

  /* u2 = r / s, P2 = u2 * Y */
  ecc_mod_mul_canonical (&ecc->q, u2, rp, sinv, u2);

   /* Total storage: 5*ecc->p.size + ECC_MUL_A_ITCH */
  ecc_mul_a (ecc, P2, u2, pp, u2 + ecc->p.size);

  /* u = 0 can happen only if h = 0 or h = q, which is extremely
     unlikely. */
  if (!mpn_zero_p (u1, ecc->p.size))
    {
      /* Total storage: 7*ecc->p.size + ECC_MUL_G_ITCH */
      ecc_mul_g (ecc, P1, u1, P1 + 3*ecc->p.size);

      /* Total storage: 6*ecc->p.size + ECC_ADD_JJJ_ITCH */
      if (!ecc_nonsec_add_jjj (ecc, P2, P2, P1, P1 + 3*ecc->p.size))
	/* Infinity point, not a valid signature. */
	return 0;
    }
  /* x coordinate only, modulo q */
  ecc_j_to_a (ecc, 2, P1, P2, P1 + 3*ecc->p.size);

  return (mpn_cmp (rp, P1, ecc->p.size) == 0);
#undef P2
#undef P1
#undef sinv
#undef u2
#undef hp
#undef u1
}
