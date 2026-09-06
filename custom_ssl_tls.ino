#include <SPI.h>
#include <Ethernet.h>
#include <avr/pgmspace.h>
#define DEBUG_TLS_ALERTS 0
byte mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};

struct U256
{
  uint8_t v[32];
};
struct Point
{
  U256 x;
  U256 y;
};
U256 ecdheSharedSecret;
uint8_t serverRandom[32];
uint16_t selectedCipherSuite = 0;
U256 tlsMasterSecretPart1;
U256 tlsMasterSecretPart2;
uint8_t tlsMasterSecret[48];
uint8_t clientWriteKey[16];
uint8_t serverWriteKey[16];

uint8_t clientWriteIV[4];
uint8_t serverWriteIV[4];
uint8_t clientRandom[32];
uint8_t tlsKeyBlock[40];


struct SHA256Context
{
  uint32_t state[8];
  uint64_t bitCount;
  uint8_t buffer[64];
};


// 256-bit integer helpers Internal representation:
//   v[0]  = least significant byte    v[31] = most significant byte
// TLS/network values are normally big-endian, so conversion functions are provided separately.


void zero256(U256 &a)
{
  for (int i = 0; i < 32; i++)
    a.v[i] = 0;
}

void copy256(U256 &dst, const U256 &src)
{
  for (int i = 0; i < 32; i++)
    dst.v[i] = src.v[i];
}

int compare256(const U256 &a, const U256 &b)
{
  for (int i = 31; i >= 0; i--)
  {
    if (a.v[i] < b.v[i])
      return -1;

    if (a.v[i] > b.v[i])
      return 1;
  }

  return 0;
}

// ---Add--- Returns the final carry:  0 = no overflow beyond 256 bits   1 = overflow
uint8_t add256(  U256 &result,  const U256 &a,  const U256 &b)
{
  uint16_t carry = 0;

  for (int i = 0; i < 32; i++)
  {
    uint16_t sum =
        (uint16_t)a.v[i] +
        (uint16_t)b.v[i] +
        carry;

    result.v[i] = (uint8_t)sum;
    carry = sum >> 8;
  }

  return (uint8_t)carry;
}


// ------Subtract---  Returns the final borrow:/   0 = a >= b    1 = a < b

uint8_t sub256(  U256 &result,  const U256 &a,  const U256 &b)
{
  int16_t borrow = 0;

  for (int i = 0; i < 32; i++)
  {
    int16_t value =
        (int16_t)a.v[i] -
        (int16_t)b.v[i] -
        borrow;

    if (value < 0)
    {
      value += 256;
      borrow = 1;
    }
    else
    {
      borrow = 0;
    }

    result.v[i] = (uint8_t)value;
  }

  return (uint8_t)borrow;
}

void fromBigEndian(  U256 &result,  const uint8_t *data)
{
  for (int i = 0; i < 32; i++)
    result.v[i] = data[31 - i];
}
void fromBigEndianProgmem(U256 &result, const uint8_t *data)
{
  for (int i = 0; i < 32; i++)
  {
    result.v[i] = pgm_read_byte(&data[31 - i]);
  }
}

void toBigEndian(  uint8_t *data,  const U256 &value)
{
  for (int i = 0; i < 32; i++)
    data[i] = value.v[31 - i];
}

const uint8_t P256_PRIME_BE[32] PROGMEM =
{
  0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF
};

const uint8_t P256_B_BE[32] PROGMEM =
{
  0x5A, 0xC6, 0x35, 0xD8,
  0xAA, 0x3A, 0x93, 0xE7,
  0xB3, 0xEB, 0xBD, 0x55,
  0x76, 0x98, 0x86, 0xBC,
  0x65, 0x1D, 0x06, 0xB0,
  0xCC, 0x53, 0xB0, 0xF6,
  0x3B, 0xCE, 0x3C, 0x3E,
  0x27, 0xD2, 0x60, 0x4B
};

const uint8_t P256_GX_BE[32] PROGMEM =
{
  0x6B, 0x17, 0xD1, 0xF2,
  0xE1, 0x2C, 0x42, 0x47,
  0xF8, 0xBC, 0xE6, 0xE5,
  0x63, 0xA4, 0x40, 0xF2,
  0x77, 0x03, 0x7D, 0x81,
  0x2D, 0xEB, 0x33, 0xA0,
  0xF4, 0xA1, 0x39, 0x45,
  0xD8, 0x98, 0xC2, 0x96
};

const uint8_t P256_GY_BE[32] PROGMEM =
{
  0x4F, 0xE3, 0x42, 0xE2,
  0xFE, 0x1A, 0x7F, 0x9B,
  0x8E, 0xE7, 0xEB, 0x4A,
  0x7C, 0x0F, 0x9E, 0x16,
  0x2B, 0xCE, 0x33, 0x57,
  0x6B, 0x31, 0x5E, 0xCE,
  0xCB, 0xB6, 0x40, 0x68,
  0x37, 0xBF, 0x51, 0xF5
};


void modAdd256(U256 &result, const U256 &a, const U256 &b)
{
  U256 pMinusB;

  // p - b
  subPrime256(pMinusB, b);

  // If a >= p-b:
  //     a+b >= p
  //     result = a - (p-b)
  //
  // Otherwise:
  //     a+b < p
  if (compare256(a, pMinusB) >= 0)
  {
    sub256(result, a, pMinusB);
  }
  else
  {
    add256(result, a, b);
  }
}
void modSub256(  U256 &result,  const U256 &a,  const U256 &b)
{
  if (compare256(a, b) >= 0)
  {
    sub256(result, a, b);
    return;
  }

  U256 temp;

  sub256(temp, b, a);
  subPrime256(result, temp);
}

void modMul256(U256 &result, const U256 &a, const U256 &b)
{
  U256 x;
  U256 y;

  copy256(x, a);
  copy256(y, b);
  zero256(result);

  // result = result * 2 + current bit of b
  // Process b from most significant bit to least significant bit.
  for (int i = 31; i >= 0; i--)
  {
    uint8_t value = y.v[i];

    for (int bit = 7; bit >= 0; bit--)
    {
      modAdd256(result, result, result);

      if (value & (1 << bit))
      {
        modAdd256(result, result, x);
      }
    }
  }
}
void set256(  U256 &result,  uint32_t value)
{
  zero256(result);

  result.v[0] = value & 0xFF;
  result.v[1] = (value >> 8) & 0xFF;
  result.v[2] = (value >> 16) & 0xFF;
  result.v[3] = (value >> 24) & 0xFF;
}
void print256(const U256 &value)
{
  for (int i = 31; i >= 0; i--)
  {
    if (value.v[i] < 0x10)
      Serial.print('0');

    Serial.print(value.v[i], HEX);
  }

  Serial.println();
}


const uint32_t SHA256_K[64] PROGMEM =
{
  0x428A2F98UL, 0x71374491UL, 0xB5C0FBCFUL, 0xE9B5DBA5UL,
  0x3956C25BUL, 0x59F111F1UL, 0x923F82A4UL, 0xAB1C5ED5UL,
  0xD807AA98UL, 0x12835B01UL, 0x243185BEUL, 0x550C7DC3UL,
  0x72BE5D74UL, 0x80DEB1FEUL, 0x9BDC06A7UL, 0xC19BF174UL,
  0xE49B69C1UL, 0xEFBE4786UL, 0x0FC19DC6UL, 0x240CA1CCUL,
  0x2DE92C6FUL, 0x4A7484AAUL, 0x5CB0A9DCUL, 0x76F988DAUL,
  0x983E5152UL, 0xA831C66DUL, 0xB00327C8UL, 0xBF597FC7UL,
  0xC6E00BF3UL, 0xD5A79147UL, 0x06CA6351UL, 0x14292967UL,
  0x27B70A85UL, 0x2E1B2138UL, 0x4D2C6DFCUL, 0x53380D13UL,
  0x650A7354UL, 0x766A0ABBUL, 0x81C2C92EUL, 0x92722C85UL,
  0xA2BFE8A1UL, 0xA81A664BUL, 0xC24B8B70UL, 0xC76C51A3UL,
  0xD192E819UL, 0xD6990624UL, 0xF40E3585UL, 0x106AA070UL,
  0x19A4C116UL, 0x1E376C08UL, 0x2748774CUL, 0x34B0BCB5UL,
  0x391C0CB3UL, 0x4ED8AA4AUL, 0x5B9CCA4FUL, 0x682E6FF3UL,
  0x748F82EEUL, 0x78A5636FUL, 0x84C87814UL, 0x8CC70208UL,
  0x90BEFFFAUL, 0xA4506CEBUL, 0xBEF9A3F7UL, 0xC67178F2UL
};

uint32_t rotr32(uint32_t x, uint8_t n)
{
  return (x >> n) | (x << (32 - n));
}

uint32_t sha256Ch(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ (~x & z);
}

uint32_t sha256Maj(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t sha256BigSigma0(uint32_t x)
{
  return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

uint32_t sha256BigSigma1(uint32_t x)
{
  return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

uint32_t sha256SmallSigma0(uint32_t x)
{
  return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

uint32_t sha256SmallSigma1(uint32_t x)
{
  return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

void sha256Init(SHA256Context &ctx)
{
  ctx.state[0] = 0x6A09E667UL;
  ctx.state[1] = 0xBB67AE85UL;
  ctx.state[2] = 0x3C6EF372UL;
  ctx.state[3] = 0xA54FF53AUL;
  ctx.state[4] = 0x510E527FUL;
  ctx.state[5] = 0x9B05688CUL;
  ctx.state[6] = 0x1F83D9ABUL;
  ctx.state[7] = 0x5BE0CD19UL;

  ctx.bitCount = 0;
}

void sha256Transform(SHA256Context &ctx, const uint8_t *data)
{
  uint32_t w[64];

  for (uint8_t i = 0; i < 16; i++)
  {
    uint8_t j = i * 4;

    w[i] =
        ((uint32_t)data[j] << 24) |
        ((uint32_t)data[j + 1] << 16) |
        ((uint32_t)data[j + 2] << 8) |
        ((uint32_t)data[j + 3]);
  }

  for (uint8_t i = 16; i < 64; i++)
  {
    w[i] =
        sha256SmallSigma1(w[i - 2]) +
        w[i - 7] +
        sha256SmallSigma0(w[i - 15]) +
        w[i - 16];
  }

  uint32_t a = ctx.state[0];
  uint32_t b = ctx.state[1];
  uint32_t c = ctx.state[2];
  uint32_t d = ctx.state[3];
  uint32_t e = ctx.state[4];
  uint32_t f = ctx.state[5];
  uint32_t g = ctx.state[6];
  uint32_t h = ctx.state[7];

  for (uint8_t i = 0; i < 64; i++)
  {
    uint32_t k = pgm_read_dword(&SHA256_K[i]);

    uint32_t t1 =
        h +
        sha256BigSigma1(e) +
        sha256Ch(e, f, g) +
        k +
        w[i];

    uint32_t t2 =
        sha256BigSigma0(a) +
        sha256Maj(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx.state[0] += a;
  ctx.state[1] += b;
  ctx.state[2] += c;
  ctx.state[3] += d;
  ctx.state[4] += e;
  ctx.state[5] += f;
  ctx.state[6] += g;
  ctx.state[7] += h;
}

void sha256Update(
    SHA256Context &ctx,
    const uint8_t *data,
    uint16_t length)
{
  uint16_t index =
      (uint16_t)((ctx.bitCount >> 3) & 0x3F);

  ctx.bitCount += (uint64_t)length * 8;

  for (uint16_t i = 0; i < length; i++)
  {
    ctx.buffer[index++] = data[i];

    if (index == 64)
    {
      sha256Transform(ctx, ctx.buffer);
      index = 0;
    }
  }
}

void sha256UpdateByte(
    SHA256Context &ctx,
    uint8_t value)
{
  sha256Update(ctx, &value, 1);
}

void sha256Final(
    SHA256Context &ctx,
    uint8_t digest[32])
{
  uint16_t index =
      (uint16_t)((ctx.bitCount >> 3) & 0x3F);

  ctx.buffer[index++] = 0x80;

  if (index > 56)
  {
    while (index < 64)
      ctx.buffer[index++] = 0;

    sha256Transform(ctx, ctx.buffer);
    index = 0;
  }

  while (index < 56)
    ctx.buffer[index++] = 0;

  uint64_t bits = ctx.bitCount;

  for (int i = 7; i >= 0; i--)
  {
    ctx.buffer[index++] = (uint8_t)(bits >> (i * 8));
  }

  sha256Transform(ctx, ctx.buffer);

  for (uint8_t i = 0; i < 8; i++)
  {
    digest[i * 4] =
        (uint8_t)(ctx.state[i] >> 24);

    digest[i * 4 + 1] =
        (uint8_t)(ctx.state[i] >> 16);

    digest[i * 4 + 2] =
        (uint8_t)(ctx.state[i] >> 8);

    digest[i * 4 + 3] =
        (uint8_t)ctx.state[i];
  }
}


void hmacSha256(const uint8_t *key, uint8_t keyLength, const uint8_t *data, uint16_t dataLength, uint8_t output[32])
{
  uint8_t keyBlock[64];

  for (uint8_t i = 0; i < 64; i++)
    keyBlock[i] = 0;

  if (keyLength > 64)
  {
    SHA256Context keyHash;
    uint8_t digest[32];

    sha256Init(keyHash);
    sha256Update(keyHash, key, keyLength);
    sha256Final(keyHash, digest);

    for (uint8_t i = 0; i < 32; i++)
      keyBlock[i] = digest[i];
  }
  else
  {
    for (uint8_t i = 0; i < keyLength; i++)
      keyBlock[i] = key[i];
  }

  SHA256Context ctx;

  for (uint8_t i = 0; i < 64; i++)
    keyBlock[i] ^= 0x36;

  sha256Init(ctx);
  sha256Update(ctx, keyBlock, 64);
  sha256Update(ctx, data, dataLength);

  uint8_t innerHash[32];
  sha256Final(ctx, innerHash);

  for (uint8_t i = 0; i < 64; i++)
    keyBlock[i] ^= 0x36 ^ 0x5C;

  sha256Init(ctx);
  sha256Update(ctx, keyBlock, 64);
  sha256Update(ctx, innerHash, 32);
  sha256Final(ctx, output);
}

void tlsPrfSha256(
    const uint8_t *secret,
    uint8_t secretLength,
    const uint8_t *label,
    uint8_t labelLength,
    const uint8_t *seed,
    uint8_t seedLength,
    uint8_t *output,
    uint16_t outputLength)
{
    uint8_t labelSeed[64];
    uint8_t A[32];
    uint8_t nextA[32];
    uint8_t input[96];
    uint8_t block[32];

    uint8_t labelSeedLength =
        labelLength + seedLength;

    for (uint8_t i = 0; i < labelLength; i++)
        labelSeed[i] = label[i];

    for (uint8_t i = 0; i < seedLength; i++)
        labelSeed[labelLength + i] = seed[i];

    /*
     * A(1) = HMAC(secret, label + seed)
     */
    hmacSha256(
        secret,
        secretLength,
        labelSeed,
        labelSeedLength,
        A
    );

    uint16_t produced = 0;

    while (produced < outputLength)
    {
        /*
         * P_hash block:
         *
         * HMAC(secret, A(i) + label + seed)
         */

        for (uint8_t i = 0; i < 32; i++)
            input[i] = A[i];

        for (uint8_t i = 0; i < labelSeedLength; i++)
            input[32 + i] = labelSeed[i];

        hmacSha256(
            secret,
            secretLength,
            input,
            32 + labelSeedLength,
            block
        );

        uint16_t remaining =
            outputLength - produced;

        uint8_t copyLength =
            remaining < 32 ? remaining : 32;

        for (uint8_t i = 0; i < copyLength; i++)
            output[produced + i] = block[i];

        produced += copyLength;

        /*
         * A(i+1) = HMAC(secret, A(i))
         */
        hmacSha256(
            secret,
            secretLength,
            A,
            32,
            nextA
        );

        for (uint8_t i = 0; i < 32; i++)
            A[i] = nextA[i];
    }
}

void deriveTLSKeys()
{
    uint8_t masterSeed[64];
    uint8_t keySeed[64];

    /*
     * master_secret =
     * PRF(pre_master_secret,
     *     "master secret",
     *     ClientHello.random + ServerHello.random)
     */

    for (uint8_t i = 0; i < 32; i++)
    {
        masterSeed[i] = clientRandom[i];
        masterSeed[32 + i] = serverRandom[i];
    }

    const uint8_t masterLabel[] = "master secret";

    tlsPrfSha256(
        ecdheSharedSecret.v,
        32,
        masterLabel,
        13,
        masterSeed,
        64,
        tlsMasterSecret,
        48
    );

    /*
     * key_block =
     * PRF(master_secret,
     *     "key expansion",
     *     ServerHello.random + ClientHello.random)
     */

    for (uint8_t i = 0; i < 32; i++)
    {
        keySeed[i] = serverRandom[i];
        keySeed[32 + i] = clientRandom[i];
    }

    const uint8_t keyLabel[] = "key expansion";

    tlsPrfSha256(
        tlsMasterSecret,
        48,
        keyLabel,
        13,
        keySeed,
        64,
        tlsKeyBlock,
        40
    );

    /*
     * Split key_block
     */

    for (uint8_t i = 0; i < 16; i++)
        clientWriteKey[i] = tlsKeyBlock[i];

    for (uint8_t i = 0; i < 16; i++)
        serverWriteKey[i] = tlsKeyBlock[16 + i];

    for (uint8_t i = 0; i < 4; i++)
        clientWriteIV[i] = tlsKeyBlock[32 + i];

    for (uint8_t i = 0; i < 4; i++)
        serverWriteIV[i] = tlsKeyBlock[36 + i];
}

EthernetClient client;

struct ECCWorkspace
{
  Point point1;
  // Point point2; //optimized out

  U256 temp1;
  U256 temp2;
  U256 temp3;
  U256 temp4;
  //uint8_t product[64]; //optimized out
};

struct PointProjective
{
  U256 x;
  U256 y;
  U256 z;
};



ECCWorkspace ecc;

Point ecdheClientPublic;
U256 ecdhePrivate;


void pointDoubleProjective(PointProjective &p);
void pointDoubleProjective(PointProjective &p)
{
  // A = X1²
  modMul256(ecc.temp1, p.x, p.x);

  // B = Y1²
  modMul256(ecc.temp2, p.y, p.y);

  // C = B²
  modMul256(ecc.temp3, ecc.temp2, ecc.temp2);

  // D = 2 * ((X1 + B)² - A - C)
  modAdd256(ecc.temp2, p.x, ecc.temp2);
  modMul256(ecc.temp2, ecc.temp2, ecc.temp2);
  modSub256(ecc.temp2, ecc.temp2, ecc.temp1);
  modSub256(ecc.temp2, ecc.temp2, ecc.temp3);
  modAdd256(ecc.temp4, ecc.temp2, ecc.temp2);

  // E = 3 * (A - Z1⁴)
  modMul256(ecc.temp2, p.z, p.z);
  modMul256(ecc.temp2, ecc.temp2, ecc.temp2);
  modSub256(ecc.temp1, ecc.temp1, ecc.temp2);

  set256(ecc.temp2, 3);
  modMul256(ecc.temp1, ecc.temp1, ecc.temp2);

  // Z3 = 2 * Y1 * Z1
  // Old Y1 is no longer needed after this.
  modMul256(ecc.temp2, p.y, p.z);
  modAdd256(p.z, ecc.temp2, ecc.temp2);

  // F = E²
  modMul256(ecc.temp2, ecc.temp1, ecc.temp1);

  // 2D — use p.y as scratch.
  modAdd256(p.y, ecc.temp4, ecc.temp4);

  // X3 = F - 2D
  modSub256(p.x, ecc.temp2, p.y);

  // Y3 = E(D - X3) - 8C
  modSub256(ecc.temp2, ecc.temp4, p.x);
  modMul256(ecc.temp2, ecc.temp1, ecc.temp2);

  // 8C
  modAdd256(ecc.temp3, ecc.temp3, ecc.temp3);
  modAdd256(ecc.temp3, ecc.temp3, ecc.temp3);
  modAdd256(ecc.temp3, ecc.temp3, ecc.temp3);

  modSub256(p.y, ecc.temp2, ecc.temp3);
}

void printMemory()
{
  extern char __heap_start;
  extern char *__brkval;

  char stackVariable;

  int freeMemory =
      &stackVariable -
      (__brkval ? __brkval : &__heap_start);

  Serial.print(F("Free SRAM: "));
  Serial.println(freeMemory);
}


// Fixed TLS 1.2 ClientHello.
// Stored in Flash instead of SRAM.
const uint8_t clientHello[] PROGMEM =
{
  0x16, 0x03, 0x01, 0x00, 0x78,

  0x01, 0x00, 0x00, 0x74,

  0x03, 0x03,

  0x00, 0x01, 0x02, 0x03,
  0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0A, 0x0B,
  0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1A, 0x1B,
  0x1C, 0x1D, 0x1E, 0x1F,

  0x00,

  0x00, 0x08,
  0xC0, 0x2F,
  0xC0, 0x30,
  0x00, 0x9C,
  0x00, 0x9D,

  0x01, 0x00,

  0x00, 0x43,

  // SNI
  0x00, 0x00,
  0x00, 0x18,
  0x00, 0x16,
  0x00,
  0x00, 0x13,
  'a','p','i','.',
  'c','o','i','n',
  'p','a','p','r',
  'i','k','a','.',
  'c','o','m',

  // Supported groups
  0x00, 0x0A,
  0x00, 0x06,
  0x00, 0x04,
  0x00, 0x17,
  0x00, 0x18,

  // EC point formats
  0x00, 0x0B,
  0x00, 0x04,
  0x03,
  0x00, 0x01, 0x02,

  // Signature algorithms
  0x00, 0x0D,
  0x00, 0x0A,
  0x00, 0x08,
  0x04, 0x01,
  0x05, 0x01,
  0x04, 0x03,
  0x05, 0x03,

  // Supported versions
  0x00, 0x2B,
  0x00, 0x03,
  0x02,
  0x03, 0x03
};

const uint16_t clientHelloLength = sizeof(clientHello);

void printHexPROGMEM(
  const uint8_t *buffer,
  uint16_t length
)
{
  for (uint16_t i = 0; i < length; i++)
  {
    uint8_t value = pgm_read_byte(&buffer[i]);

    if (value < 0x10)
      Serial.print('0');

    Serial.print(value, HEX);
    Serial.print(' ');

    if ((i + 1) % 16 == 0)
      Serial.println();
  }
}

size_t sendClientHello()
{
  size_t sent = 0;

  /*
   * ClientHello.random starts at byte 11
   * and is 32 bytes long.
   */
  for (uint8_t i = 0; i < 32; i++)
    clientRandom[i] = pgm_read_byte(&clientHello[11 + i]);

  for (uint16_t i = 0; i < clientHelloLength; i++)
  {
    uint8_t value = pgm_read_byte(&clientHello[i]);

    if (client.write(value) == 1)
      sent++;
    else
      break;
  }

  return sent;
}

// Print bytes
void printHex(uint8_t *buffer, int length)
{
  for (int i = 0; i < length; i++)
  {
    if (buffer[i] < 0x10)
      Serial.print('0');

    Serial.print(buffer[i], HEX);
    Serial.print(' ');

    if ((i + 1) % 16 == 0)
      Serial.println();
  }

  Serial.println();
}

bool readTLSByte(uint8_t &value)
{
  unsigned long start = millis();

  while (!client.available())
  {
    if (!client.connected())
      return false;

    if (millis() - start >= 5000)
      return false;

    delay(1);
  }

  value = client.read();
  return true;
}


bool readTLSU16(uint16_t &value)
{
  uint8_t highByte;
  uint8_t lowByte;

  if (!readTLSByte(highByte))
    return false;

  if (!readTLSByte(lowByte))
    return false;

  value =
      ((uint16_t)highByte << 8) |
      lowByte;

  return true;
}


bool readTLSU24(uint32_t &value)
{
  uint8_t b0;
  uint8_t b1;
  uint8_t b2;

  if (!readTLSByte(b0))
    return false;

  if (!readTLSByte(b1))
    return false;

  if (!readTLSByte(b2))
    return false;

  value =
      ((uint32_t)b0 << 16) |
      ((uint32_t)b1 << 8) |
      b2;

  return true;
}


bool consumeTLSBytes(uint16_t count)
{
  uint8_t value;

  for (uint16_t i = 0; i < count; i++)
  {
    if (!readTLSByte(value))
      return false;
  }

  return true;
}

void parseCertificate(const uint8_t *data, size_t len)
{
    Serial.println();
    Serial.println(F("=== Certificate ==="));
    size_t p = 0;
    if (len < 4)
    {
        Serial.println(F("Certificate message too short."));
        return;
    }
    // TLS Handshake header
    uint8_t handshakeType = data[p++];

    uint32_t handshakeLength =
        ((uint32_t)data[p] << 16) |
        ((uint32_t)data[p + 1] << 8) |
        data[p + 2];
    p += 3;
    Serial.print(F("Handshake type: 0x"));
    Serial.println(handshakeType, HEX);
    Serial.print(F("Handshake length: "));
    Serial.println(handshakeLength);
    if (handshakeType != 0x0B)
    {
        Serial.println(F("Not a Certificate message."));
        return;
    }
    if (p + 3 > len)
    {
        Serial.println(F("Missing certificate list length."));
        return;
    }
    // certificate_list_length
    uint32_t certificateListLength =
        ((uint32_t)data[p] << 16) |
        ((uint32_t)data[p + 1] << 8) |
        data[p + 2];
    p += 3;
    Serial.print(F("Certificate list length: "));
    Serial.println(certificateListLength);

    size_t listEnd = p + certificateListLength;

    if (listEnd > len)
    {
        Serial.println(F("Certificate list exceeds received data."));
        return;
    }

    int certificateNumber = 0;

    while (p < listEnd)
    {
        if (p + 3 > listEnd)
        {
            Serial.println(F("Missing certificate length."));
            return;
        }

        uint32_t certificateLength =
            ((uint32_t)data[p] << 16) |
            ((uint32_t)data[p + 1] << 8) |
            data[p + 2];

        p += 3;

        certificateNumber++;

        Serial.print(F("Certificate #"));
        Serial.print(certificateNumber);
        Serial.print(F(" length: "));
        Serial.println(certificateLength);

        if (p + certificateLength > listEnd)
        {
            Serial.println(F("Certificate exceeds certificate list."));
            return;
        }

        Serial.print(F("Certificate #"));
        Serial.print(certificateNumber);
        Serial.println(F(" first bytes:"));

        size_t previewLength = certificateLength < 16
                             ? certificateLength
                             : 16;

        for (size_t i = 0; i < previewLength; i++)
        {
            if (data[p + i] < 0x10)
                Serial.print('0');

            Serial.print(data[p + i], HEX);
            Serial.print(' ');
        }

        Serial.println();

        p += certificateLength;
        // Each TLS Certificate entry also has:
        // extensions length : uint16
        // in newer TLS certificate structures.
        // However, for TLS 1.2's Certificate message,
        // the certificate_list entries are:
        // certificate_length + certificate
        // so there is no per-certificate extensions field here.
    }

    Serial.print(F("Certificates found: "));
    Serial.println(certificateNumber);

    if (p == listEnd)
        Serial.println(F("Certificate list parsed successfully."));
    else
        Serial.println(F("Certificate list parsing ended unexpectedly."));
}


bool readTLSRecordHeader( uint8_t &contentType, uint8_t &versionMajor, uint8_t &versionMinor, uint16_t &recordLength)
{
  unsigned long start = millis();

  // Wait until the complete 5-byte TLS header is available
  while (client.available() < 5)
  {
    if (!client.connected())
      return false;

    if (millis() - start >= 5000)
      return false;

    delay(10);
  }


  contentType = client.read();
  versionMajor = client.read();
  versionMinor = client.read();

  uint8_t lengthHigh = client.read();
  uint8_t lengthLow = client.read();

  recordLength =
      ((uint16_t)lengthHigh << 8) |
      lengthLow;

  return true;
}

uint8_t primeByte256(int i)
{
  // P256_PRIME_BE is big-endian,
  // while U256 is little-endian.
  return pgm_read_byte(&P256_PRIME_BE[31 - i]);
}

int comparePrime256(const U256 &a)
{
  for (int i = 31; i >= 0; i--)
  {
    uint8_t p = primeByte256(i);

    if (a.v[i] < p)
      return -1;

    if (a.v[i] > p)
      return 1;
  }

  return 0;
}

uint8_t subPrime256(U256 &result, const U256 &a)
{
  int16_t borrow = 0;

  for (int i = 0; i < 32; i++)
  {
    int16_t value =
        (int16_t)primeByte256(i)
        - (int16_t)a.v[i]
        - borrow;

    if (value < 0)
    {
      value += 256;
      borrow = 1;
    }
    else
    {
      borrow = 0;
    }

    result.v[i] = (uint8_t)value;
  }

  return (uint8_t)borrow;
}
void getPMinus2(U256 &result)
{
  zero256(result);
  result.v[0] = 2;

  U256 temp;
  copy256(temp, result);

  subPrime256(result, temp);
}

uint8_t pMinus2Byte256(int i)
{
  uint8_t value = pgm_read_byte(&P256_PRIME_BE[i]);

  if (i == 31)
  {
    value -= 2;
  }

  return value;
}

void modInverse256(U256 &result, const U256 &a)
{
  U256 base;

  copy256(base, a);

  zero256(result);
  result.v[0] = 1;

  // Process p - 2 from most significant bit to least significant bit.
  for (int i = 0; i < 32; i++)
  {
    uint8_t exponentByte = pMinus2Byte256(i);

    for (int bit = 7; bit >= 0; bit--)
    {
      // result = result² mod p
      modMul256(result, result, result);

      if (exponentByte & (1 << bit))
      {
        // result = result * base mod p
        modMul256(result, result, base);
      }
    }
  }
}

void pointDouble(Point &result, const Point &p)
{
  // temp1 = x²
  modMul256(ecc.temp1, p.x, p.x);

  // temp4 = 3
  set256(ecc.temp4, 3);

  // temp2 = 3x²
  modMul256(ecc.temp2, ecc.temp1, ecc.temp4);

  // temp2 = 3x² - 3
  modSub256(ecc.temp2, ecc.temp2, ecc.temp4);

  // temp3 = 2y
  modAdd256(ecc.temp3, p.y, p.y);

  // temp4 = inverse(2y)
  modInverse256(ecc.temp4, ecc.temp3);

  // temp2 = λ
  modMul256(ecc.temp2, ecc.temp2, ecc.temp4);

  // temp3 = λ²
  modMul256(ecc.temp3, ecc.temp2, ecc.temp2);

  // temp4 = 2x
  modAdd256(ecc.temp4, p.x, p.x);

  // result.x = λ² - 2x
  modSub256(result.x, ecc.temp3, ecc.temp4);

  // temp3 = x - result.x
  modSub256(ecc.temp3, p.x, result.x);

  // temp4 = λ(x - result.x)
  modMul256(ecc.temp4, ecc.temp2, ecc.temp3);

  // result.y = λ(x - result.x) - y
  modSub256(result.y, ecc.temp4, p.y);
}

void pointProjectiveToAffine(Point &result, const PointProjective &p);
void pointProjectiveToAffine(Point &result, const PointProjective &p)
{
  // temp1 = 1 / Z
  modInverse256(ecc.temp1, p.z);

  // temp2 = 1 / Z²
  modMul256(ecc.temp2, ecc.temp1, ecc.temp1);

  // x = X / Z²
  modMul256(result.x, p.x, ecc.temp2);

  // temp1 = 1 / Z³
  modMul256(ecc.temp1, ecc.temp2, ecc.temp1);

  // y = Y / Z³
  modMul256(result.y, p.y, ecc.temp1);
}
void pointAdd(Point &result, const Point &p, const Point &q)
{
  // λ = (qy - py) / (qx - px)
  modSub256(ecc.temp1, q.y, p.y);
  modSub256(ecc.temp2, q.x, p.x);

  // inverse(qx - px)
  modInverse256(ecc.temp4, ecc.temp2);

  // λ
  modMul256(ecc.temp1, ecc.temp1, ecc.temp4);

  // λ²
  modMul256(ecc.temp3, ecc.temp1, ecc.temp1);

  // x3 = λ² - px - qx
  modSub256(ecc.temp4, ecc.temp3, p.x);
  modSub256(result.x, ecc.temp4, q.x);

  // λ(px - x3)
  modSub256(ecc.temp3, p.x, result.x);
  modMul256(ecc.temp4, ecc.temp1, ecc.temp3);

  // y3 = λ(px - x3) - py
  modSub256(result.y, ecc.temp4, p.y);
}
bool isZero256(const U256 &a)
{
  for (int i = 0; i < 32; i++)
  {
    if (a.v[i] != 0)
      return false;
  }

  return true;
}
void pointAddAffineProjective(PointProjective &result, const Point &p);
void pointAddAffineProjective(PointProjective &result, const Point &p)
{
  // If result is infinity, infinity + P = P.
  if (isZero256(result.z))
  {
    copy256(result.x, p.x);
    copy256(result.y, p.y);

    zero256(result.z);
    result.z.v[0] = 1;

    return;
  }

  // Z1²
  modMul256(ecc.temp1, result.z, result.z);

  // U2 = X2 * Z1²
  modMul256(ecc.temp2, p.x, ecc.temp1);

  // Z1³
  modMul256(ecc.temp3, ecc.temp1, result.z);

  // S2 = Y2 * Z1³
  modMul256(ecc.temp3, p.y, ecc.temp3);

  // H = U2 - X1
  modSub256(ecc.temp2, ecc.temp2, result.x);

  // R = S2 - Y1
  modSub256(ecc.temp3, ecc.temp3, result.y);

  // H == 0?
  if (isZero256(ecc.temp2))
  {
    // Same point: R == 0 => doubling.
    if (isZero256(ecc.temp3))
    {
      pointDoubleProjective(result);
      return;
    }

    // Same X but different Y => point at infinity.
    zero256(result.x);
    zero256(result.y);
    zero256(result.z);

    return;
  }

  // H²
  modMul256(ecc.temp1, ecc.temp2, ecc.temp2);

  // H³
  modMul256(ecc.temp4, ecc.temp1, ecc.temp2);

  // Z3 = Z1 * H
  // temp2 still contains H here.
  modMul256(ecc.temp2, result.z, ecc.temp2);
  copy256(result.z, ecc.temp2);

  // V = X1 * H²
  // Keep V in temp1 because result.x must become X3.
  modMul256(ecc.temp1, result.x, ecc.temp1);

  // X3 = R² - H³ - 2V
  modMul256(result.x, ecc.temp3, ecc.temp3);
  modSub256(result.x, result.x, ecc.temp4);

  modAdd256(ecc.temp2, ecc.temp1, ecc.temp1);

  modSub256(result.x, result.x, ecc.temp2);

  // Y3 = R(V - X3) - Y1*H³
  modSub256(ecc.temp2, ecc.temp1, result.x);

  modMul256(ecc.temp2, ecc.temp3, ecc.temp2);

  modMul256(ecc.temp1, result.y, ecc.temp4);

  modSub256(result.y, ecc.temp2, ecc.temp1);
}

void pointSetProjectiveGenerator(PointProjective &p);
void pointSetProjectiveGenerator(PointProjective &p)
{
  fromBigEndianProgmem(p.x, P256_GX_BE);
  fromBigEndianProgmem(p.y, P256_GY_BE);

  zero256(p.z);
  p.z.v[0] = 1;
}

void pointAddAffineProjectiveProgmem(PointProjective &result, const uint8_t *px, const uint8_t *py);
void pointAddAffineProjectiveProgmem(PointProjective &result, const uint8_t *px, const uint8_t *py)
{
  // Infinity + P = P
  if (isZero256(result.z))
  {
    fromBigEndianProgmem(result.x, px);
    fromBigEndianProgmem(result.y, py);

    zero256(result.z);
    result.z.v[0] = 1;

    return;
  }

  // Z1²
  modMul256(ecc.temp1, result.z, result.z);

  // U2 = X2 * Z1²
  fromBigEndianProgmem(ecc.temp2, px);
  modMul256(ecc.temp2, ecc.temp2, ecc.temp1);

  // Z1³
  // temp4 is used instead of scalar.
  modMul256(ecc.temp4, ecc.temp1, result.z);

  // S2 = Y2 * Z1³
  fromBigEndianProgmem(ecc.temp3, py);
  modMul256(ecc.temp3, ecc.temp3, ecc.temp4);

  // H = U2 - X1
  modSub256(ecc.temp2, ecc.temp2, result.x);

  // R = S2 - Y1
  modSub256(ecc.temp3, ecc.temp3, result.y);

  // H == 0?
  if (isZero256(ecc.temp2))
  {
    // Same point: R == 0 => doubling.
    if (isZero256(ecc.temp3))
    {
      pointDoubleProjective(result);
      return;
    }

    // Same X but different Y => point at infinity.
    zero256(result.x);
    zero256(result.y);
    zero256(result.z);

    return;
  }

  // H²
  modMul256(ecc.temp1, ecc.temp2, ecc.temp2);

  // H³
  modMul256(ecc.temp4, ecc.temp1, ecc.temp2);

  // Z3 = Z1 * H
  // temp2 still contains H here.
  modMul256(ecc.temp2, result.z, ecc.temp2);
  copy256(result.z, ecc.temp2);

  // V = X1 * H²
  // Keep V in temp1 because result.x must become X3.
  modMul256(ecc.temp1, result.x, ecc.temp1);

  // X3 = R² - H³ - 2V
  modMul256(result.x, ecc.temp3, ecc.temp3);
  modSub256(result.x, result.x, ecc.temp4);

  modAdd256(ecc.temp2, ecc.temp1, ecc.temp1);

  modSub256(result.x, result.x, ecc.temp2);

  // Y3 = R(V - X3) - Y1*H³
  modSub256(ecc.temp2, ecc.temp1, result.x);

  modMul256(ecc.temp2, ecc.temp3, ecc.temp2);

  modMul256(ecc.temp1, result.y, ecc.temp4);

  modSub256(result.y, ecc.temp2, ecc.temp1);
}


//void pointScalarMultiplyProjective(PointProjective &result, const U256 &scalar);
// void pointScalarMultiplyProjectiveOld(PointProjective &result, const U256 &scalar)
// {
//   zero256(result.x);
//   zero256(result.y);
//   zero256(result.z);

//   bool started = false;

//   for (int byteIndex = 31; byteIndex >= 0; byteIndex--)
//   {
//     uint8_t value = scalar.v[byteIndex];

//     for (int bit = 7; bit >= 0; bit--)
//     {
//       if (!started)
//       {
//         if ((value & (1 << bit)) == 0)
//           continue;

//         pointSetProjectiveGenerator(result);
//         started = true;
//         continue;
//       }

//       pointDoubleProjective(result);

//       if (value & (1 << bit))
//       {
//         pointAddAffineProjectiveProgmem(
//             result,
//             P256_GX_BE,
//             P256_GY_BE);
//       }
//     }
//   }
// }
void __attribute__((noinline)) pointScalarMultiplyProjective(
    PointProjective &result,
    const U256 &scalar,
    const Point &point);
void __attribute__((noinline)) pointScalarMultiplyProjective(
    PointProjective &result,
    const U256 &scalar,
    const Point &point)
{
  zero256(result.x);
  zero256(result.y);
  zero256(result.z);

  bool started = false;

  for (int byteIndex = 31; byteIndex >= 0; byteIndex--)
  {
    uint8_t value = scalar.v[byteIndex];

    for (int bit = 7; bit >= 0; bit--)
    {
      if (!started)
      {
        if ((value & (1 << bit)) == 0)
          continue;

        copy256(result.x, point.x);
        copy256(result.y, point.y);

        zero256(result.z);
        result.z.v[0] = 1;

        started = true;
        continue;
      }

      pointDoubleProjective(result);

      if (value & (1 << bit))
      {
        pointAddAffineProjective(result, point);
      }
    }
  }
}

void pointProjectiveToAffineX(U256 &result, const PointProjective &p);
void pointProjectiveToAffineX(U256 &result, const PointProjective &p)
{
  // 1 / Z
  modInverse256(ecc.temp1, p.z);
  // 1 / Z²
  modMul256(ecc.temp2, ecc.temp1, ecc.temp1);
  // X / Z²
  modMul256(result, p.x, ecc.temp2);
}


void testScalarMultiplication()
{
  Serial.println(F("=== Scalar multiplication test ==="));

  U256 k;
  zero256(k);

  // k = 3
  //k.v[0] = 5;
  for (int i = 0; i < 32; i++)
    k.v[i] = 0x01;

  Point g;

  // Load P-256 generator from existing PROGMEM constants.
  // The constants are stored big-endian, while U256 is little-endian.
  for (int i = 0; i < 32; i++)
  {
    g.x.v[i] = pgm_read_byte(&P256_GX_BE[31 - i]);
    g.y.v[i] = pgm_read_byte(&P256_GY_BE[31 - i]);
  }

  PointProjective r;

  // r = k × G
  pointScalarMultiplyProjective(r, k, g);

  U256 x;

  // Convert only X coordinate back to affine.
  pointProjectiveToAffineX(x, r);

  Serial.println(F("2G X:"));
  print256(x);

  Serial.println(F("=== End scalar multiplication test ==="));
}
void printU256Hex(const U256 &a)
{
  for (int i = 0; i < 32; i++)
  {
    if (a.v[i] < 16)
      Serial.print('0');

    Serial.print(a.v[i], HEX);
  }

  Serial.println();
}
void testScalarMultiplicationProjective()
{
  Serial.println(F("Testing P-256 scalar multiplication..."));

  U256 scalar;
  Point generator;
  PointProjective result;
  Point affine;

  // k = 1
  zero256(scalar);
  scalar.v[31] = 1;

  // P-256 generator
  fromBigEndianProgmem(generator.x, P256_GX_BE);
  fromBigEndianProgmem(generator.y, P256_GY_BE);

  pointScalarMultiplyProjective(result, scalar, generator);

  pointProjectiveToAffine(affine, result);

  Serial.println(F("X:"));
  printU256Hex(affine.x);

  Serial.println(F("Y:"));
  printU256Hex(affine.y);
}

size_t sendClientKeyExchange(const Point &publicKey)
{
  size_t sent = 0;

  // TLS record header
  if (client.write((uint8_t)0x16) == 1) sent++;
  if (client.write((uint8_t)0x03) == 1) sent++;
  if (client.write((uint8_t)0x03) == 1) sent++;
  if (client.write((uint8_t)0x00) == 1) sent++;
  if (client.write((uint8_t)0x46) == 1) sent++;

  // Handshake header
  if (client.write((uint8_t)0x10) == 1) sent++;
  if (client.write((uint8_t)0x00) == 1) sent++;
  if (client.write((uint8_t)0x00) == 1) sent++;
  if (client.write((uint8_t)0x42) == 1) sent++;

  // ECPoint length = 65 bytes
  if (client.write((uint8_t)0x41) == 1) sent++;

  // Uncompressed point
  if (client.write((uint8_t)0x04) == 1) sent++;

  // X coordinate, big-endian
  for (int i = 31; i >= 0; i--)
  {
    if (client.write(publicKey.x.v[i]) == 1)
      sent++;
  }

  // Y coordinate, big-endian
  for (int i = 31; i >= 0; i--)
  {
    if (client.write(publicKey.y.v[i]) == 1)
      sent++;
  }

  return sent;
}

void setup()
{
  Serial.begin(115200);
  delay(1000);

  Serial.println(F("Starting Ethernet..."));

  if (Ethernet.begin(mac) == 0)
  {
    Serial.println(F("DHCP failed!"));

    Serial.print(F("IP address: "));
    Serial.println(Ethernet.localIP());

    return;
  }
  delay(1000);

  Serial.print(F("IP address: "));
  Serial.println(Ethernet.localIP());


  // =======================================================
  // TCP CONNECTION
  // =======================================================

  Serial.println();

  Serial.println(
    "Connecting to api.coinpaprika.com:443..."
  );
  if (!client.connect("api.binance.com", 443))
  //if (!client.connect("api.coinpaprika.com", 443))
  {
    Serial.println(F("TCP connection failed!"));
    return;
  }
  printMemory();
  Serial.println(F("TCP connection established!"));


  // =======================================================
  // CLIENT HELLO
  // =======================================================

  Serial.println();

  Serial.print(F("ClientHello size: "));
  Serial.println(clientHelloLength);

  Serial.println();

  Serial.println(F("ClientHello bytes:"));
  printHexPROGMEM(clientHello, clientHelloLength);


  // =======================================================
  // SEND CLIENT HELLO
  // =======================================================

  Serial.println();

  Serial.println(F("Sending ClientHello..."));

  size_t sent = sendClientHello();

  Serial.print(F("Bytes sent: "));
  Serial.println(sent);

  Serial.println(F("ClientHello sent!"));




  // =======================================================
  // WAIT FOR TLS RESPONSE
  // =======================================================

  Serial.println();

  Serial.println(F("Waiting for TLS response..."));

  unsigned long start = millis();
  printMemory();

  while (millis() - start < 15000)
  {
    if (client.available())
    {
      Serial.println();

      Serial.println(F("Received TLS bytes:"));

      while (client.connected())
      {
        uint8_t contentType;
        uint8_t versionMajor;
        uint8_t versionMinor;
        uint16_t recordLength;


        if (!readTLSRecordHeader(
              contentType,
              versionMajor,
              versionMinor,
              recordLength))
        {
          Serial.println(F("Could not read TLS record header."));
          break;
        }


        Serial.println();
        Serial.println(F("=== TLS Record ==="));

        Serial.print(F("Content type: 0x"));

        if (contentType < 0x10)
          Serial.print('0');

        Serial.println(contentType, HEX);


        Serial.print(F("TLS version: "));

        Serial.print(versionMajor);
        Serial.print(F("."));
        Serial.println(versionMinor);


        Serial.print(F("Record length: "));
        Serial.println(recordLength);


        // For now, just consume the record payload.
        // We will parse it properly in the next step.

        // =======================================================
        // READ TLS RECORD PAYLOAD
        // =======================================================

        // =======================================================
        // READ TLS RECORD PAYLOAD
        // =======================================================

        if (contentType == 0x16)
        {
          // -------------------------------------------------------
          // Handshake record
          // -------------------------------------------------------

          uint8_t firstByte;

          if (!readTLSByte(firstByte))
          {
              Serial.println(F("Could not read handshake type."));
              break;
          }

          // ServerHelloDone = handshake type 0x0E
          if (firstByte == 0x0E)
          {
              Serial.println();
              Serial.println(F("ServerHelloDone received."));

              // We already consumed the handshake type.
              // ServerHelloDone has a 3-byte handshake length,
              // which must be zero.
              uint8_t b1;
              uint8_t b2;
              uint8_t b3;

              if (!readTLSByte(b1) ||
                  !readTLSByte(b2) ||
                  !readTLSByte(b3))
              {
                  Serial.println(F("Could not read ServerHelloDone length."));
                  break;
              }

              if (b1 != 0 || b2 != 0 || b3 != 0)
              {
                  Serial.println(F("Invalid ServerHelloDone length."));
                  break;
              }

              Serial.println(F("ServerHelloDone parsed."));

              // -------------------------------------------------------
              // ClientKeyExchange
              // -------------------------------------------------------

              Serial.println(F("Sending ClientKeyExchange..."));

              size_t sent = sendClientKeyExchange(ecdheClientPublic);

              Serial.print(F("ClientKeyExchange bytes sent: "));
              Serial.println(sent);

              if (sent != 75)
              {
                  Serial.println(F("ERROR: ClientKeyExchange was not fully sent."));
              }
              else
              {
                  Serial.println(F("ClientKeyExchange sent!"));
              }
          }
          else if (firstByte == 0x02)
          {
              Serial.println();
              Serial.println(F("ServerHello received."));

              // -------------------------------------------------------
              // ServerHello handshake length
              // -------------------------------------------------------

              uint32_t handshakeLength;

              if (!readTLSU24(handshakeLength))
              {
                  Serial.println(F("Could not read ServerHello length."));
                  break;
              }

              Serial.print(F("Handshake length: "));
              Serial.println(handshakeLength);

              // -------------------------------------------------------
              // Server version
              // -------------------------------------------------------

              uint8_t versionMajor;
              uint8_t versionMinor;

              if (!readTLSByte(versionMajor) ||
                  !readTLSByte(versionMinor))
              {
                  Serial.println(F("Could not read ServerHello version."));
                  break;
              }

              Serial.print(F("Server TLS version: "));
              Serial.print(versionMajor);
              Serial.print(F("."));
              Serial.println(versionMinor);

              // -------------------------------------------------------
              // Server random
              // -------------------------------------------------------

              for (uint8_t i = 0; i < 32; i++)
              {
                  if (!readTLSByte(serverRandom[i]))
                  {
                      Serial.println(F("Could not read server random."));
                      break;
                  }
              }

              Serial.println(F("Server random:"));

              for (uint8_t i = 0; i < 32; i++)
              {
                  if (serverRandom[i] < 0x10)
                      Serial.print('0');

                  Serial.print(serverRandom[i], HEX);
              }

              Serial.println();

              // -------------------------------------------------------
              // Session ID
              // -------------------------------------------------------

              uint8_t sessionIdLength;

              if (!readTLSByte(sessionIdLength))
              {
                  Serial.println(F("Could not read session ID length."));
                  break;
              }

              Serial.print(F("Session ID length: "));
              Serial.println(sessionIdLength);

              if (!consumeTLSBytes(sessionIdLength))
              {
                  Serial.println(F("Could not consume session ID."));
                  break;
              }

              // -------------------------------------------------------
              // Selected cipher suite
              // -------------------------------------------------------

              if (!readTLSU16(selectedCipherSuite))
              {
                  Serial.println(F("Could not read cipher suite."));
                  break;
              }

              Serial.print(F("Selected cipher suite: 0x"));

              if (selectedCipherSuite < 0x1000)
                  Serial.print('0');

              Serial.println(selectedCipherSuite, HEX);

              // -------------------------------------------------------
              // Compression method
              // -------------------------------------------------------

              uint8_t compressionMethod;

              if (!readTLSByte(compressionMethod))
              {
                  Serial.println(F("Could not read compression method."));
                  break;
              }

              Serial.print(F("Compression method: 0x"));
              Serial.println(compressionMethod, HEX);

              // -------------------------------------------------------
              // ServerHello extensions
              // -------------------------------------------------------

              uint16_t extensionsLength;

              if (!readTLSU16(extensionsLength))
              {
                  Serial.println(F("Could not read extensions length."));
                  break;
              }

              Serial.print(F("Extensions length: "));
              Serial.println(extensionsLength);

              if (!consumeTLSBytes(extensionsLength))
              {
                  Serial.println(F("Could not consume ServerHello extensions."));
                  break;
              }

              Serial.println(F("ServerHello parsed."));
          }
          else if (firstByte == 0x0C)
          {
            Serial.println();
            Serial.println(F("ServerKeyExchange received."));

            // We consumed handshake type, so the streaming parser
            // expects the 3-byte handshake length next.
            //
            // Reconstruct the parser manually from this point.

            uint32_t handshakeLength;

            if (!readTLSU24(handshakeLength))
            {
              Serial.println(F("Could not read SKE handshake length."));
              break;
            }

            Serial.print(F("Handshake length: "));
            Serial.println(handshakeLength);

            if (handshakeLength != (uint32_t)(recordLength - 4))
            {
              Serial.println(F("SKE length mismatch."));
              break;
            }

            // The streaming parser below handles the SKE BODY.
            // We have already consumed its 4-byte handshake header.

            uint8_t curveType;

            if (!readTLSByte(curveType))
              break;

            uint16_t namedCurve;

            if (!readTLSU16(namedCurve))
              break;

            Serial.print(F("Curve type: 0x"));
            Serial.println(curveType, HEX);

            Serial.print(F("Named curve: 0x"));
            Serial.println(namedCurve, HEX);

            if (curveType != 0x03 || namedCurve != 0x0017)
            {
              Serial.println(F("Unsupported EC parameters."));
              break;
            }

            uint8_t pointLength;

            if (!readTLSByte(pointLength))
              break;

            if (pointLength != 65)
            {
              Serial.println(F("Unexpected EC point length."));
              break;
            }

            uint8_t pointFormat;

            if (!readTLSByte(pointFormat))
              break;

            if (pointFormat != 0x04)
            {
              Serial.println(F("Expected uncompressed EC point."));
              break;
            }

            // X coordinated loop
            for (int i = 0; i < 32; i++)
            {
              uint8_t value;

              if (!readTLSByte(value))
              {
                Serial.println(F("Failed to read server EC point X."));
                return;
              }

              ecc.point1.x.v[31 - i] = value;
            }

            // Y
            for (int i = 0; i < 32; i++)
            {
              uint8_t value;

              if (!readTLSByte(value))
              {
                Serial.println(F("Failed to read server EC point Y."));
                return;
              }

              ecc.point1.y.v[31 - i] = value;
            }

            Serial.println(F("Server public X:"));
            print256(ecc.point1.x);

            Serial.println(F("Server public Y:"));
            print256(ecc.point1.y);

            // =======================================================
            // ECDHE TEST
            // =======================================================

            zero256(ecdhePrivate);

            // Temporary test private scalar = 2.
            ecdhePrivate.v[0] = 2;

            Point generator;

            fromBigEndianProgmem(generator.x, P256_GX_BE);
            fromBigEndianProgmem(generator.y, P256_GY_BE);

            PointProjective ecdhePoint;

            // -------------------------------------------------------
            // Client public key = private scalar × G
            // -------------------------------------------------------

            Serial.println(F("Calculating client public key..."));

            pointScalarMultiplyProjective(
                ecdhePoint,
                ecdhePrivate,
                generator
            );

            pointProjectiveToAffine(ecdheClientPublic, ecdhePoint);

            Serial.println(F("Client public X:"));
            print256(ecdheClientPublic.x);

            Serial.println(F("Client public Y:"));
            print256(ecdheClientPublic.y);

            // -------------------------------------------------------
            // Shared secret = private scalar × server public key
            // -------------------------------------------------------

            Serial.println(F("Calculating shared secret..."));

            pointScalarMultiplyProjective(
                ecdhePoint,
                ecdhePrivate,
                ecc.point1
            );

            pointProjectiveToAffineX(
                ecdheSharedSecret,
                ecdhePoint
            );

            Serial.println(F("Shared secret X:"));
            print256(ecdheSharedSecret);

            Serial.println(F("ECDHE calculation complete."));

            Serial.println("Deriving TLS master secret and key block...");

            deriveTLSKeys();

            Serial.println("TLS master secret:");
            for (uint8_t i = 0; i < 48; i++)
            {
                if (tlsMasterSecret[i] < 0x10)
                    Serial.print("0");
                Serial.print(tlsMasterSecret[i], HEX);
            }
            Serial.println();

            Serial.println("Client write key:");
            for (uint8_t i = 0; i < 16; i++)
            {
                if (clientWriteKey[i] < 0x10)
                    Serial.print("0");
                Serial.print(clientWriteKey[i], HEX);
            }
            Serial.println();

            Serial.println("Server write key:");
            for (uint8_t i = 0; i < 16; i++)
            {
                if (serverWriteKey[i] < 0x10)
                    Serial.print("0");
                Serial.print(serverWriteKey[i], HEX);
            }
            Serial.println();

            Serial.println("Client write IV:");
            for (uint8_t i = 0; i < 4; i++)
            {
                if (clientWriteIV[i] < 0x10)
                    Serial.print("0");
                Serial.print(clientWriteIV[i], HEX);
            }
            Serial.println();

            Serial.println("Server write IV:");
            for (uint8_t i = 0; i < 4; i++)
            {
                if (serverWriteIV[i] < 0x10)
                    Serial.print("0");
                Serial.print(serverWriteIV[i], HEX);
            }
            Serial.println();

            Serial.println("TLS key derivation complete.");

            uint8_t hashAlgorithm;
            uint8_t signatureAlgorithm;

            if (!readTLSByte(hashAlgorithm))
              break;

            if (!readTLSByte(signatureAlgorithm))
              break;

            Serial.print(F("Signature hash algorithm: 0x"));
            Serial.println(hashAlgorithm, HEX);

            Serial.print(F("Signature algorithm: 0x"));
            Serial.println(signatureAlgorithm, HEX);

            uint16_t signatureLength;

            if (!readTLSU16(signatureLength))
              break;

            Serial.print(F("Signature length: "));
            Serial.println(signatureLength);

            if (!consumeTLSBytes(signatureLength))
            {
              Serial.println(F("Could not consume RSA signature."));
              break;
            }

            Serial.println(F("RSA signature consumed."));

          }
          else
          {
            // We already consumed the handshake type.
            // Consume the remaining handshake record.
            for (uint16_t i = 1; i < recordLength; i++)
            {
              uint8_t value;

              if (!readTLSByte(value))
              {
                Serial.println(F("Failed to consume handshake record."));
                return;
              }
            }
            Serial.print(F("Handshake type: 0x"));
            Serial.println(firstByte, HEX);
          }
        }
        #if DEBUG_TLS_ALERTS
        else if (contentType == 0x15)
        {
            Serial.println();
            Serial.println(F("TLS Alert received."));

            if (recordLength != 2)
            {
                Serial.print(F("Unexpected Alert length: "));
                Serial.println(recordLength);

                if (!consumeTLSBytes(recordLength))
                {
                    Serial.println(F("Could not consume Alert."));
                    break;
                }

                continue;
            }

            uint8_t alertLevel;
            uint8_t alertDescription;

            if (!readTLSByte(alertLevel) ||
                !readTLSByte(alertDescription))
            {
                Serial.println(F("Could not read TLS Alert."));
                break;
            }

            Serial.print(F("Alert level: 0x"));
            if (alertLevel < 0x10)
                Serial.print('0');
            Serial.println(alertLevel, HEX);

            Serial.print(F("Alert description: 0x"));
            if (alertDescription < 0x10)
                Serial.print('0');
            Serial.println(alertDescription, HEX);

            Serial.print(F("Alert: "));

            switch (alertDescription)
            {
                case 0x00: Serial.println(F("close_notify")); break;
                case 0x0A: Serial.println(F("unexpected_message")); break;
                case 0x14: Serial.println(F("bad_record_mac")); break;
                case 0x16: Serial.println(F("record_overflow")); break;
                case 0x28: Serial.println(F("handshake_failure")); break;
                case 0x2A: Serial.println(F("bad_certificate")); break;
                case 0x2B: Serial.println(F("unsupported_certificate")); break;
                case 0x2C: Serial.println(F("certificate_revoked")); break;
                case 0x2D: Serial.println(F("certificate_expired")); break;
                case 0x2E: Serial.println(F("certificate_unknown")); break;
                case 0x2F: Serial.println(F("illegal_parameter")); break;
                case 0x30: Serial.println(F("unknown_ca")); break;
                case 0x31: Serial.println(F("access_denied")); break;
                case 0x32: Serial.println(F("decode_error")); break;
                case 0x33: Serial.println(F("decrypt_error")); break;
                case 0x46: Serial.println(F("protocol_version")); break;
                case 0x47: Serial.println(F("insufficient_security")); break;
                case 0x50: Serial.println(F("user_canceled")); break;
                case 0x5A: Serial.println(F("missing_extension")); break;
                case 0x6A: Serial.println(F("unsupported_extension")); break;
                case 0x70: Serial.println(F("unrecognized_name")); break;
                case 0x74: Serial.println(F("certificate_required")); break;
                case 0x78: Serial.println(F("no_application_protocol")); break;
                default:   Serial.println(F("unknown")); break;
            }
        }
        #else
        else if (contentType == 0x15)
        {
            consumeTLSBytes(recordLength);
        }
        #endif
        else
        {
          // -------------------------------------------------------
          // Non-handshake record
          // -------------------------------------------------------

          for (uint16_t i = 0; i < recordLength; i++)
          {
            uint8_t value;

            if (!readTLSByte(value))
            {
              Serial.println(F("Failed to consume TLS record."));
              return;
            }
          }

          Serial.println(F("TLS record consumed without buffering."));
        }


        // Don't immediately exit.
        // There can be multiple TLS records.
      }
    }


    if (!client.connected())
    {
      Serial.println();

      Serial.println(F("TCP connection was closed by server."));

      break;
    }

    delay(10);
  }


  // =======================================================
  // FINAL CONNECTION STATUS
  // =======================================================

  if (client.connected())
  {
    Serial.println();

    Serial.println(F("TCP connection still open."));
  }
  else
  {
    Serial.println();

    Serial.println(F("TCP connection closed."));
  }


  client.stop();
}


void loop()
{
}