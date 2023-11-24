// 定義BLAKE2bp的參數和常數
#define BLAKE2B_OUTBYTES 64
#define BLAKE2B_KEYBYTES 64
#define BLAKE2B_SALTBYTES 16
#define BLAKE2B_PERSONALBYTES 16
#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_ROUNDS 12
#define BLAKE2B_PARALLEL_DEGREE 4

static const uint64_t blake2b_IV[8] = {
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
  {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
  { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
  { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
  {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
  {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
  { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
  {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

typedef struct blake2b_state__ {
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t  buf[BLAKE2B_BLOCKBYTES];
  size_t   buflen;
  size_t   outlen;
  uint8_t  last_node;
} blake2b_state;

typedef struct blake2bp_state__ {
  blake2b_state S[BLAKE2B_PARALLEL_DEGREE];
  blake2b_state R;
  uint8_t  buf[BLAKE2B_BLOCKBYTES * BLAKE2B_PARALLEL_DEGREE];
  size_t   buflen;
  size_t   outlen;
} blake2bp_state;

// 定義BLAKE2bp的內部函數
static inline int blake2bp_init_leaf( blake2b_state *S, size_t outlen, size_t keylen, uint64_t offset )
{
  blake2b_param P[1];
  P->digest_length = ( uint8_t ) outlen;
  P->key_length    = ( uint8_t ) keylen;
  P->fanout        = BLAKE2B_PARALLEL_DEGREE;
  P->depth         = 2;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, offset );
  P->node_depth    = 0;
  P->inner_length  = BLAKE2B_OUTBYTES;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2b_init_param( S, P );
}

static inline int blake2bp_init_root( blake2b_state *S, size_t outlen, size_t keylen )
{
  blake2b_param P[1];
  P->digest_length = ( uint8_t ) outlen;
  P->key_length    = ( uint8_t ) keylen;
  P->fanout        = BLAKE2B_PARALLEL_DEGREE;
  P->depth         = 2;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 1;
  P->inner_length  = BLAKE2B_OUTBYTES;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2b_init_param( S, P );
}

static inline int blake2bp_init( blake2bp_state *S, size_t outlen )
{
  if( !outlen || outlen > BLAKE2B_OUTBYTES ) return -1;

  S->outlen = outlen;

  for( size_t i = 0; i < BLAKE2B_PARALLEL_DEGREE; ++i )
    if( blake2bp_init_leaf( S->S + i, outlen, 0, i ) < 0 ) return -1;

  return blake2bp_init_root( S->R, outlen, 0 );
}

static inline int blake2bp_update( blake2bp_state *S, const uint8_t *in, size_t inlen )
{
  size_t i;

  while( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = sizeof( S->buf ) - left;

    if( inlen > fill )
    {
      memcpy( S->buf + left, in, fill ); // Fill buffer
      S->buflen += fill;
      blake2bp_increment_counter( S, BLAKE2B_BLOCKBYTES * BLAKE2B_PARALLEL_DEGREE );
      blake2bp_compress( S ); // Compress
      S->buflen = 0;
      in += fill;
      inlen -= fill;
    }
    else // inlen <= fill
    {
      memcpy( S->buf + left, in, inlen );
      S->buflen += inlen; // Be lazy, do not compress
      in += inlen;
      inlen -= inlen;
    }
  }

  return 0;
}

static inline int blake2bp_final( blake2bp_state *S, uint8_t *out, size_t outlen )
{
  uint8_t hash[BLAKE2B_OUTBYTES * BLAKE2B_PARALLEL_DEGREE];

  if( out == NULL || outlen < S->outlen ) return -1;

  for( size_t i = 0; i < BLAKE2B_PARALLEL_DEGREE; ++i )
  {
    if( blake2b_final( S->S + i, hash + i * BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES ) < 0 )
      return -1;
  }

  if( blake2b_update( S->R, hash, BLAKE2B_OUTBYTES * BLAKE2B_PARALLEL_DEGREE ) < 0 )
    return -1;

  if( blake2b_final( S->R, hash, BLAKE2B_OUTBYTES ) < 0 )
    return -1;

  memcpy( out, hash, S->outlen );
  return 0;
}

// 定義nerd_sha256的結構體
typedef struct nerd_sha256__ {
  blake2bp_state S; // 使用BLAKE2bp作為內部狀態
  uint8_t m_buf[SHA256_DIGEST_LENGTH];
  size_t m_buflen;
  bool m_is_initialized;

void nerd_sha256_init(nerd_sha256* ctx)
{
  ctx->S = {};
  ctx->m_buflen = 0;
  ctx->m_is_initialized = false;
}

void nerd_sha256_update(nerd_sha256* ctx, const uint8_t* data, size_t len)
{
  if (!ctx->m_is_initialized) {
    blake2bp_init(&ctx->S, SHA256_DIGEST_LENGTH);
    ctx->m_is_initialized = true;
  }

  blake2bp_update(&ctx->S, data, len);
}

void nerd_sha256_final(nerd_sha256* ctx, uint8_t* hash)
{
  blake2bp_final(&ctx->S, hash, SHA256_DIGEST_LENGTH);
}

bool nerd_sha256_compare_hashes(const uint8_t* actual, const uint8_t* expected)
{
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    if (actual[i] != expected[i]) {
      return false;
    }
  }
  return true;
}
