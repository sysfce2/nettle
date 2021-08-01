C Get 32-bit floating-point register from vector register
C SFP(VR)
define(`SFP',``s'substr($1,1,len($1))')

C Get 128-bit floating-point register from vector register
C QFP(VR)
define(`QFP',``q'substr($1,1,len($1))')

C AES encryption round of 4-blocks
C AESE_ROUND_4B(BLOCK0, BLOCK1, BLOCK2, BLOCK3, KEY)
define(`AESE_ROUND_4B', m4_assert_numargs(5)`
    aese           $1.16b,$5.16b
    aesmc          $1.16b,$1.16b
    aese           $2.16b,$5.16b
    aesmc          $2.16b,$2.16b
    aese           $3.16b,$5.16b
    aesmc          $3.16b,$3.16b
    aese           $4.16b,$5.16b
    aesmc          $4.16b,$4.16b
')

C AES last encryption round of 4-blocks
C AESE_LAST_ROUND_4B(BLOCK0, BLOCK1, BLOCK2, BLOCK3, KEY0, KEY1)
define(`AESE_LAST_ROUND_4B', m4_assert_numargs(6)`
    aese           $1.16b,$5.16b
    eor            $1.16b,$1.16b,$6.16b
    aese           $2.16b,$5.16b
    eor            $2.16b,$2.16b,$6.16b
    aese           $3.16b,$5.16b
    eor            $3.16b,$3.16b,$6.16b
    aese           $4.16b,$5.16b
    eor            $4.16b,$4.16b,$6.16b
')

C AES encryption round of 1-block
C AESE_ROUND_1B(BLOCK, KEY)
define(`AESE_ROUND_1B', m4_assert_numargs(2)`
    aese           $1.16b,$2.16b
    aesmc          $1.16b,$1.16b
')

C AES last encryption round of 1-block
C AESE_LAST_ROUND_1B(BLOCK, KEY0, KEY1)
define(`AESE_LAST_ROUND_1B', m4_assert_numargs(3)`
    aese           $1.16b,$2.16b
    eor            $1.16b,$1.16b,$3.16b
')

C AES decryption round of 4-blocks
C AESD_ROUND_4B(BLOCK0, BLOCK1, BLOCK2, BLOCK3, KEY)
define(`AESD_ROUND_4B', m4_assert_numargs(5)`
    aesd           $1.16b,$5.16b
    aesimc         $1.16b,$1.16b
    aesd           $2.16b,$5.16b
    aesimc         $2.16b,$2.16b
    aesd           $3.16b,$5.16b
    aesimc         $3.16b,$3.16b
    aesd           $4.16b,$5.16b
    aesimc         $4.16b,$4.16b
')

C AES last decryption round of 4-blocks
C AESD_LAST_ROUND_4B(BLOCK0, BLOCK1, BLOCK2, BLOCK3, KEY0, KEY1)
define(`AESD_LAST_ROUND_4B', m4_assert_numargs(6)`
    aesd           $1.16b,$5.16b
    eor            $1.16b,$1.16b,$6.16b
    aesd           $2.16b,$5.16b
    eor            $2.16b,$2.16b,$6.16b
    aesd           $3.16b,$5.16b
    eor            $3.16b,$3.16b,$6.16b
    aesd           $4.16b,$5.16b
    eor            $4.16b,$4.16b,$6.16b
')

C AES decryption round of 1-block
C AESD_ROUND_1B(BLOCK, KEY)
define(`AESD_ROUND_1B', m4_assert_numargs(2)`
    aesd           $1.16b,$2.16b
    aesimc         $1.16b,$1.16b
')

C AES last decryption round of 1-block
C AESD_LAST_ROUND_1B(BLOCK, KEY0, KEY1)
define(`AESD_LAST_ROUND_1B', m4_assert_numargs(3)`
    aesd           $1.16b,$2.16b
    eor            $1.16b,$1.16b,$3.16b
')
