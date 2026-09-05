#include <SPI.h>
#include <Ethernet.h>
#include <avr/pgmspace.h>

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
  U256 r;

  copy256(x, a);
  copy256(y, b);
  zero256(r);

  for (int i = 0; i < 256; i++)
  {
    if (y.v[0] & 1)
    {
      modAdd256(r, r, x);
    }

    // x = 2*x mod p
    modAdd256(x, x, x);

    // y >>= 1
    uint8_t carry = 0;

    for (int j = 31; j >= 0; j--)
    {
      uint8_t newCarry = y.v[j] & 1;
      y.v[j] = (y.v[j] >> 1) | (carry << 7);
      carry = newCarry;
    }
  }

  copy256(result, r);
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
EthernetClient client;

struct ECCWorkspace
{
  U256 scalar;
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

PointProjective jacobian;

ECCWorkspace ecc;
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

  set256(ecc.scalar, 3);
  modMul256(ecc.scalar, ecc.temp1, ecc.scalar);

  // F = E²
  modMul256(ecc.temp1, ecc.scalar, ecc.scalar);

  // X3 = F - 2D
  modAdd256(ecc.temp2, ecc.temp4, ecc.temp4);
  modSub256(p.x, ecc.temp1, ecc.temp2);

  // Z3 = 2Y1Z1
  modMul256(ecc.temp2, p.y, p.z);
  modAdd256(p.z, ecc.temp2, ecc.temp2);

  // Y3 = E(D - X3) - 8C
  modSub256(ecc.temp2, ecc.temp4, p.x);
  modMul256(ecc.temp2, ecc.scalar, ecc.temp2);

  // 8C
  modAdd256(ecc.temp1, ecc.temp3, ecc.temp3);
  modAdd256(ecc.temp1, ecc.temp1, ecc.temp1);
  modAdd256(ecc.temp1, ecc.temp1, ecc.temp1);

  modSub256(p.y, ecc.temp2, ecc.temp1);
}
void printMemory()
{
  extern int __heap_start, *__brkval;

  int v;

  int freeMemory;

  if ((int)__brkval == 0)
    freeMemory = ((int)&v) - ((int)&__heap_start);
  else
    freeMemory = ((int)&v) - ((int)__brkval);

  Serial.print("Free SRAM: ");
  Serial.println(freeMemory);
}

// Append 16-bit big-endian integer and 24-bit next 
void append16(uint8_t *buffer, int &pos, uint16_t value)
{
  buffer[pos++] = (value >> 8) & 0xFF;
  buffer[pos++] = value & 0xFF;
}

void append24(uint8_t *buffer, int &pos, uint32_t value)
{
  buffer[pos++] = (value >> 16) & 0xFF;
  buffer[pos++] = (value >> 8) & 0xFF;
  buffer[pos++] = value & 0xFF;
}

// Build TLS 1.2 ClientHello
int buildClientHello(uint8_t *buffer)
{
  const char *hostname = "api.coinpaprika.com";
  uint8_t hostnameLength = strlen(hostname);
  int pos = 0;
  // TLS RECORD HEADER
  buffer[pos++] = 0x16;   // Handshake
  buffer[pos++] = 0x03;   // TLS 1.0 record version
  buffer[pos++] = 0x01;

  int recordLengthPos = pos;
  pos += 2;               // Filled later
  // HANDSHAKE HEADER
  buffer[pos++] = 0x01;   // ClientHello
  int handshakeLengthPos = pos;
  pos += 3;               // Filled later
  int handshakeBodyStart = pos;
  // CLIENT VERSION

  buffer[pos++] = 0x03;
  buffer[pos++] = 0x03;   // TLS 1.2
  // RANDOM
  for (int i = 0; i < 32; i++)
  {
    buffer[pos++] = i;
  }
  // SESSION ID
  buffer[pos++] = 0x00;
  // CIPHER SUITES
  append16(buffer, pos, 8); // Cipher suite list length = 8 bytes
  append16(buffer, pos, 0xC02F);
  append16(buffer, pos, 0xC030);
  append16(buffer, pos, 0x009C);
  append16(buffer, pos, 0x009D);
  // COMPRESSION METHODS
  buffer[pos++] = 0x01;   // list length
  buffer[pos++] = 0x00;   // null compression
  // EXTENSIONS
  int extensionsLengthPos = pos;
  pos += 2;               // Filled later
  int extensionsStart = pos;
  // SNI - Server Name Indication
  append16(buffer, pos, 0x0000);   // extension type
  append16(buffer, pos, hostnameLength + 5); // extension length
  append16(buffer, pos, hostnameLength + 3); // server name list
  buffer[pos++] = 0x00;             // host_name
  append16(buffer, pos, hostnameLength);
  for (int i = 0; i < hostnameLength; i++)
  {
    buffer[pos++] = hostname[i];
  }
  // SUPPORTED GROUPS
  append16(buffer, pos, 0x000A);   // extension type
  append16(buffer, pos, 6);        // extension length
  append16(buffer, pos, 4);        // groups vector length
  append16(buffer, pos, 0x0017);   // secp256r1
  append16(buffer, pos, 0x0018);   // secp384r1
  // EC POINT FORMATS
  append16(buffer, pos, 0x000B);   // extension type
  append16(buffer, pos, 4);        // extension length
  buffer[pos++] = 0x03;             // 3 formats
  buffer[pos++] = 0x00;             // uncompressed
  buffer[pos++] = 0x01;             // ansiX962_compressed_prime
  buffer[pos++] = 0x02;             // ansiX962_compressed_char2
  // SIGNATURE ALGORITHMS
  append16(buffer, pos, 0x000D);   // extension type
  append16(buffer, pos, 10);       // extension length
  append16(buffer, pos, 8);        // signature algorithms length
  append16(buffer, pos, 0x0401);   // rsa_pkcs1_sha256
  append16(buffer, pos, 0x0501);   // rsa_pkcs1_sha384
  append16(buffer, pos, 0x0403);   // ecdsa_secp256r1_sha256
  append16(buffer, pos, 0x0503);   // ecdsa_secp384r1_sha384
  // SUPPORTED VERSIONS
  append16(buffer, pos, 0x002B);   // supported_versions
  append16(buffer, pos, 3);        // extension length
  buffer[pos++] = 0x02;            // versions vector length
  buffer[pos++] = 0x03;
  buffer[pos++] = 0x03;            // TLS 1.2
  // FIX EXTENSIONS LENGTH
  int extensionsLength = pos - extensionsStart;
  buffer[extensionsLengthPos] =
      (extensionsLength >> 8) & 0xFF;
  buffer[extensionsLengthPos + 1] =
      extensionsLength & 0xFF;
  // FIX HANDSHAKE LENGTH
  int handshakeLength = pos - handshakeBodyStart;
  buffer[handshakeLengthPos] =
      (handshakeLength >> 16) & 0xFF;
  buffer[handshakeLengthPos + 1] =
      (handshakeLength >> 8) & 0xFF;
  buffer[handshakeLengthPos + 2] =
      handshakeLength & 0xFF;
  // FIX TLS RECORD LENGTH
  int recordLength = pos - 5;
  buffer[recordLengthPos] =
      (recordLength >> 8) & 0xFF;
  buffer[recordLengthPos + 1] =
      recordLength & 0xFF;
  return pos;
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


void parseCertificate(const uint8_t *data, size_t len)
{
    Serial.println();
    Serial.println("=== Certificate ===");
    size_t p = 0;
    if (len < 4)
    {
        Serial.println("Certificate message too short.");
        return;
    }
    // TLS Handshake header
    uint8_t handshakeType = data[p++];

    uint32_t handshakeLength =
        ((uint32_t)data[p] << 16) |
        ((uint32_t)data[p + 1] << 8) |
        data[p + 2];
    p += 3;
    Serial.print("Handshake type: 0x");
    Serial.println(handshakeType, HEX);
    Serial.print("Handshake length: ");
    Serial.println(handshakeLength);
    if (handshakeType != 0x0B)
    {
        Serial.println("Not a Certificate message.");
        return;
    }
    if (p + 3 > len)
    {
        Serial.println("Missing certificate list length.");
        return;
    }
    // certificate_list_length
    uint32_t certificateListLength =
        ((uint32_t)data[p] << 16) |
        ((uint32_t)data[p + 1] << 8) |
        data[p + 2];
    p += 3;
    Serial.print("Certificate list length: ");
    Serial.println(certificateListLength);

    size_t listEnd = p + certificateListLength;

    if (listEnd > len)
    {
        Serial.println("Certificate list exceeds received data.");
        return;
    }

    int certificateNumber = 0;

    while (p < listEnd)
    {
        if (p + 3 > listEnd)
        {
            Serial.println("Missing certificate length.");
            return;
        }

        uint32_t certificateLength =
            ((uint32_t)data[p] << 16) |
            ((uint32_t)data[p + 1] << 8) |
            data[p + 2];

        p += 3;

        certificateNumber++;

        Serial.print("Certificate #");
        Serial.print(certificateNumber);
        Serial.print(" length: ");
        Serial.println(certificateLength);

        if (p + certificateLength > listEnd)
        {
            Serial.println("Certificate exceeds certificate list.");
            return;
        }

        Serial.print("Certificate #");
        Serial.print(certificateNumber);
        Serial.println(" first bytes:");

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

    Serial.print("Certificates found: ");
    Serial.println(certificateNumber);

    if (p == listEnd)
        Serial.println("Certificate list parsed successfully.");
    else
        Serial.println("Certificate list parsing ended unexpectedly.");
}

void parseServerKeyExchange(const uint8_t *data, size_t len)
{
    Serial.println();
    Serial.println("=== ServerKeyExchange ===");
    size_t p = 0;
    if (len < 4)
    {
        Serial.println("Too short.");
        return;
    }
    // Handshake header
    uint8_t handshakeType = data[p++];

    uint32_t handshakeLength =
        ((uint32_t)data[p] << 16) |
        ((uint32_t)data[p + 1] << 8) |
        data[p + 2];

    p += 3;

    Serial.print("Handshake type: 0x");
    Serial.println(handshakeType, HEX);

    Serial.print("Handshake length: ");
    Serial.println(handshakeLength);

    if (handshakeType != 0x0C)
    {
        Serial.println("Not ServerKeyExchange.");
        return;
    }

    if (p + 3 > len)
    {
        Serial.println("Truncated.");
        return;
    }

    // ECParameters
    uint8_t curveType = data[p++];

    uint16_t namedCurve =
        ((uint16_t)data[p] << 8) |
        data[p + 1];

    p += 2;

    Serial.print("Curve type: 0x");
    Serial.println(curveType, HEX);

    Serial.print("Named curve: 0x");
    Serial.println(namedCurve, HEX);

    // ECPoint
    uint8_t pointLength = data[p++];

    Serial.print("EC point length: ");
    Serial.println(pointLength);

    if (p + pointLength > len)
    {
        Serial.println("Truncated EC point.");
        return;
    }

    Serial.println("EC public key:");

    for (size_t i = 0; i < pointLength; i++)
    {
        if (data[p + i] < 0x10)
            Serial.print('0');

        Serial.print(data[p + i], HEX);
        Serial.print(' ');

        if ((i + 1) % 16 == 0)
            Serial.println();
    }

    Serial.println();

    p += pointLength;

    // Signature algorithm
    if (p + 2 > len)
    {
        Serial.println("Missing signature algorithm.");
        return;
    }

    uint8_t hashAlgorithm = data[p++];
    uint8_t signatureAlgorithm = data[p++];

    Serial.print("Signature hash algorithm: 0x");
    Serial.println(hashAlgorithm, HEX);

    Serial.print("Signature algorithm: 0x");
    Serial.println(signatureAlgorithm, HEX);

    // Signature length
    if (p + 2 > len)
    {
        Serial.println("Missing signature length.");
        return;
    }

    uint16_t signatureLength =
        ((uint16_t)data[p] << 8) |
        data[p + 1];

    p += 2;

    Serial.print("Signature length: ");
    Serial.println(signatureLength);

    if (p + signatureLength > len)
    {
        Serial.println("Truncated signature.");
        return;
    }

    Serial.println("RSA signature:");

    for (size_t i = 0; i < signatureLength; i++)
    {
        if (data[p + i] < 0x10)
            Serial.print('0');

        Serial.print(data[p + i], HEX);
        Serial.print(' ');

        if ((i + 1) % 16 == 0)
            Serial.println();
    }

    Serial.println();
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
  U256 r;

  copy256(base, a);

  zero256(r);
  r.v[0] = 1;

  // Process p - 2 from most significant bit to least significant bit.
  for (int i = 0; i < 32; i++)
  {
    uint8_t exponentByte = pMinus2Byte256(i);

    for (int bit = 7; bit >= 0; bit--)
    {
      // r = r² mod p
      modMul256(r, r, r);

      if (exponentByte & (1 << bit))
      {
        // r = r * base mod p
        modMul256(r, r, base);
      }
    }
  }

  copy256(result, r);
}

void pointDouble(Point &result, const Point &p)
{
  // temp1 = x²
  modMul256(ecc.temp1, p.x, p.x);

  // scalar = 3
  set256(ecc.scalar, 3);

  // temp2 = 3x²
  modMul256(ecc.temp2, ecc.temp1, ecc.scalar);

  // temp2 = 3x² - 3
  modSub256(ecc.temp2, ecc.temp2, ecc.scalar);

  // temp3 = 2y
  modAdd256(ecc.temp3, p.y, p.y);

  // scalar = inverse(2y)
  modInverse256(ecc.scalar, ecc.temp3);

  // temp2 = λ
  modMul256(ecc.temp2, ecc.temp2, ecc.scalar);

  // temp3 = λ²
  modMul256(ecc.temp3, ecc.temp2, ecc.temp2);

  // scalar = 2x
  modAdd256(ecc.scalar, p.x, p.x);

  // result.x = λ² - 2x
  modSub256(result.x, ecc.temp3, ecc.scalar);

  // temp3 = x - result.x
  modSub256(ecc.temp3, p.x, result.x);

  // scalar = λ(x - result.x)
  modMul256(ecc.scalar, ecc.temp2, ecc.temp3);

  // result.y = λ(x - result.x) - y
  modSub256(result.y, ecc.scalar, p.y);
}

void pointAdd(Point &result, const Point &p, const Point &q)
{
  // temp1 = y2 - y1
  modSub256(ecc.temp1, q.y, p.y);

  // temp2 = x2 - x1
  modSub256(ecc.temp2, q.x, p.x);

  // scalar = inverse(x2 - x1)
  modInverse256(ecc.scalar, ecc.temp2);

  // temp1 = λ
  modMul256(ecc.temp1, ecc.temp1, ecc.scalar);

  // temp3 = λ²
  modMul256(ecc.temp3, ecc.temp1, ecc.temp1);

  // scalar = λ² - x1
  modSub256(ecc.scalar, ecc.temp3, p.x);

  // result.x = λ² - x1 - x2
  modSub256(result.x, ecc.scalar, q.x);

  // temp3 = x1 - result.x
  modSub256(ecc.temp3, p.x, result.x);

  // scalar = λ(x1 - result.x)
  modMul256(ecc.scalar, ecc.temp1, ecc.temp3);

  // result.y = λ(x1 - result.x) - y1
  modSub256(result.y, ecc.scalar, p.y);
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

void testJacobian()
{
  fromBigEndianProgmem(jacobian.x, P256_GX_BE);
  fromBigEndianProgmem(jacobian.y, P256_GY_BE);
  set256(jacobian.z, 1);

  Serial.println("Starting Jacobian doubling...");

  pointDoubleProjective(jacobian);

  Serial.println("Jacobian 2G:");
  print256(jacobian.x);
  print256(jacobian.y);
  print256(jacobian.z);

  Point affine2G;

  Serial.println("Converting to affine...");

  pointProjectiveToAffine(affine2G, jacobian);

  Serial.println("Affine 2G:");
  print256(affine2G.x);
  print256(affine2G.y);

  printMemory();
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

  // --------------------------------------------------
  // Z1²
  // temp1 = Z1²
  // --------------------------------------------------
  modMul256(ecc.temp1, result.z, result.z);

  // --------------------------------------------------
  // U2 = X2 * Z1²
  // temp2 = U2
  // --------------------------------------------------
  modMul256(ecc.temp2, p.x, ecc.temp1);

  // --------------------------------------------------
  // Z1³
  // temp3 = Z1³
  // --------------------------------------------------
  modMul256(ecc.temp3, ecc.temp1, result.z);

  // --------------------------------------------------
  // S2 = Y2 * Z1³
  // temp3 = S2
  // --------------------------------------------------
  modMul256(ecc.temp3, p.y, ecc.temp3);

  // --------------------------------------------------
  // H = U2 - X1
  // temp2 = H
  // --------------------------------------------------
  modSub256(ecc.temp2, ecc.temp2, result.x);

  // --------------------------------------------------
  // R = S2 - Y1
  // temp3 = R
  // --------------------------------------------------
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

  // --------------------------------------------------
  // H²
  // temp1 = H²
  // --------------------------------------------------
  modMul256(ecc.temp1, ecc.temp2, ecc.temp2);

  // --------------------------------------------------
  // H³
  // temp4 = H³
  // --------------------------------------------------
  modMul256(ecc.temp4, ecc.temp1, ecc.temp2);

  // --------------------------------------------------
  // V = X1 * H²
  // scalar = V
  // --------------------------------------------------
  modMul256(ecc.scalar, result.x, ecc.temp1);

  // --------------------------------------------------
  // Z3 = Z1 * H
  //
  // Do this BEFORE temp2 is reused.
  // --------------------------------------------------
  modMul256(result.z, result.z, ecc.temp2);

  // --------------------------------------------------
  // X3 = R² - H³ - 2V
  // --------------------------------------------------
  modMul256(result.x, ecc.temp3, ecc.temp3);

  modSub256(result.x, result.x, ecc.temp4);

  modAdd256(ecc.temp2, ecc.scalar, ecc.scalar);

  modSub256(result.x, result.x, ecc.temp2);

  // --------------------------------------------------
  // Y3 = R(V - X3) - Y1*H³
  // --------------------------------------------------
  modSub256(ecc.temp2, ecc.scalar, result.x);

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
  // --------------------------------------------------
  // Infinity + P = P
  // --------------------------------------------------
  if (isZero256(result.z))
  {
    fromBigEndianProgmem(result.x, px);
    fromBigEndianProgmem(result.y, py);

    zero256(result.z);
    result.z.v[0] = 1;

    return;
  }

  // --------------------------------------------------
  // Z1²
  //
  // temp1 = Z1²
  // --------------------------------------------------
  modMul256(ecc.temp1, result.z, result.z);

  // --------------------------------------------------
  // U2 = X2 * Z1²
  //
  // Load X2 directly from PROGMEM into temp2.
  // temp2 = U2
  // --------------------------------------------------
  fromBigEndianProgmem(ecc.temp2, px);
  modMul256(ecc.temp2, ecc.temp2, ecc.temp1);

  // --------------------------------------------------
  // Z1³
  //
  // scalar = Z1³
  // --------------------------------------------------
  modMul256(ecc.scalar, ecc.temp1, result.z);

  // --------------------------------------------------
  // S2 = Y2 * Z1³
  //
  // Load Y2 directly from PROGMEM into temp3.
  // temp3 = S2
  // --------------------------------------------------
  fromBigEndianProgmem(ecc.temp3, py);
  modMul256(ecc.temp3, ecc.temp3, ecc.scalar);

  // --------------------------------------------------
  // H = U2 - X1
  //
  // temp2 = H
  // --------------------------------------------------
  modSub256(ecc.temp2, ecc.temp2, result.x);

  // --------------------------------------------------
  // R = S2 - Y1
  //
  // temp3 = R
  // --------------------------------------------------
  modSub256(ecc.temp3, ecc.temp3, result.y);

  // --------------------------------------------------
  // Special cases
  // --------------------------------------------------
  if (isZero256(ecc.temp2))
  {
    // H = 0 and R = 0 means P == result.
    // Therefore result = 2 * result.
    if (isZero256(ecc.temp3))
    {
      pointDoubleProjective(result);
      return;
    }

    // H = 0 and R != 0 means P == -result.
    // Result is the point at infinity.
    zero256(result.x);
    zero256(result.y);
    zero256(result.z);

    return;
  }

  // --------------------------------------------------
  // H²
  //
  // temp1 = H²
  // --------------------------------------------------
  modMul256(ecc.temp1, ecc.temp2, ecc.temp2);

  // --------------------------------------------------
  // H³
  //
  // temp4 = H³
  // --------------------------------------------------
  modMul256(ecc.temp4, ecc.temp1, ecc.temp2);

  // --------------------------------------------------
  // V = X1 * H²
  //
  // scalar = V
  // --------------------------------------------------
  modMul256(ecc.scalar, result.x, ecc.temp1);

  // --------------------------------------------------
  // Z3 = Z1 * H
  //
  // Do this before temp2 is reused.
  // --------------------------------------------------
  modMul256(result.z, result.z, ecc.temp2);

  // --------------------------------------------------
  // X3 = R² - H³ - 2V
  // --------------------------------------------------
  modMul256(result.x, ecc.temp3, ecc.temp3);

  modSub256(result.x, result.x, ecc.temp4);

  // temp2 = 2V
  modAdd256(ecc.temp2, ecc.scalar, ecc.scalar);

  modSub256(result.x, result.x, ecc.temp2);

  // --------------------------------------------------
  // Y3 = R(V - X3) - Y1*H³
  // --------------------------------------------------

  // temp2 = V - X3
  modSub256(ecc.temp2, ecc.scalar, result.x);

  // temp2 = R(V - X3)
  modMul256(ecc.temp2, ecc.temp3, ecc.temp2);

  // temp1 = Y1 * H³
  modMul256(ecc.temp1, result.y, ecc.temp4);

  // Y3
  modSub256(result.y, ecc.temp2, ecc.temp1);
}


void pointScalarMultiplyProjective(PointProjective &result, const U256 &scalar);
void pointScalarMultiplyProjective(PointProjective &result, const U256 &scalar)
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

        pointSetProjectiveGenerator(result);
        started = true;
        continue;
      }

      pointDoubleProjective(result);

      if (value & (1 << bit))
      {
        pointAddAffineProjectiveProgmem(
            result,
            P256_GX_BE,
            P256_GY_BE);
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
  U256 k;
  PointProjective r;
  U256 x;

  Serial.println();
  Serial.println(F("=== P-256 SCALAR MULTIPLICATION ==="));

  // 2G
  set256(k, 2);
  pointScalarMultiplyProjective(r, k);
  pointProjectiveToAffineX(x, r);
  Serial.println(F("2G:"));
  print256(x);

  // 3G
  set256(k, 3);
  pointScalarMultiplyProjective(r, k);
  pointProjectiveToAffineX(x, r);
  Serial.println(F("3G:"));
  print256(x);

  // 5G
  set256(k, 5);
  pointScalarMultiplyProjective(r, k);
  pointProjectiveToAffineX(x, r);
  Serial.println(F("5G:"));
  print256(x);
}

void setup()
{
  Serial.begin(9600);
  //fromBigEndian(P256_PRIME, P256_PRIME_BE);
  Serial.println("=== 256-BIT ARITHMETIC TEST ===");

  U256 a;
  U256 b;
  U256 result;

  // compare
  set256(a, 1);
  set256(b, 2);
  Serial.print("compare(1,2) = ");
  Serial.println(compare256(a, b));
  Serial.print("compare(2,1) = ");
  Serial.println(compare256(b, a));
  Serial.print("compare(1,1) = ");
  Serial.println(compare256(a, a));

  // addition
  set256(a, 1);
  set256(b, 2);
  add256(result, a, b);
  Serial.print("1 + 2 = ");
  print256(result);
  // subtraction
  set256(a, 10);
  set256(b, 3);
  sub256(result, a, b);
  Serial.print("10 - 3 = ");
  print256(result);
  // modular subtraction
  zero256(a);
  set256(b, 1);
  modSub256(result, a, b);
  Serial.print("0 - 1 mod p = ");
  print256(result);

  U256 pMinus1;
  U256 two;

  // p - 1
  set256(two, 1);
  subPrime256(pMinus1, two);

  // 1) (p - 1) * 2 mod p = p - 2
  set256(two, 2);

  modMul256(result, pMinus1, two);

  Serial.print("(p - 1) * 2 mod p = ");
  print256(result);

  modMul256(result, pMinus1, pMinus1);

  Serial.print("(p - 1) * (p - 1) mod p = ");
  print256(result);
  
  Serial.println("Starting Ethernet...");
  Serial.println("=== ECC MEMORY TEST ===");
  Ethernet.begin(mac);
  printMemory();

  Serial.print("sizeof(U256): ");
  Serial.println(sizeof(U256));

  Serial.print("sizeof(Point): ");
  Serial.println(sizeof(Point));

  Serial.print("sizeof(ECCWorkspace): ");
  Serial.println(sizeof(ECCWorkspace));

  printMemory();

  {
    Point affine2G;

    pointProjectiveToAffine(affine2G, jacobian);

    Serial.println("Affine 2G:");
    print256(affine2G.x);
    print256(affine2G.y);
  }

  testJacobian();

  PointProjective r;

  pointSetProjectiveGenerator(r);

  Point g;

  fromBigEndianProgmem(g.x, P256_GX_BE);
  fromBigEndianProgmem(g.y, P256_GY_BE);

  pointAddAffineProjective(r, g);

  Point affine;

  pointProjectiveToAffine(affine, r);

  Serial.println(F("G + G:"));

  print256(affine.x);
  print256(affine.y);
  printMemory();

  testScalarMultiplication();
  printMemory();
  return;

  delay(1000);

  Serial.print("IP address: ");
  Serial.println(Ethernet.localIP());


  // =======================================================
  // TCP CONNECTION
  // =======================================================

  Serial.println();

  Serial.println(
    "Connecting to api.coinpaprika.com:443..."
  );

  if (!client.connect("api.coinpaprika.com", 443))
  {
    Serial.println("TCP connection failed!");
    return;
  }
  printMemory();
  Serial.println("TCP connection established!");


  // =======================================================
  // BUILD CLIENT HELLO
  // =======================================================

  uint8_t clientHello[160];

  int clientHelloLength =
      buildClientHello(clientHello);


  Serial.println();

  Serial.print("ClientHello size: ");
  Serial.println(clientHelloLength);


  Serial.println();

  Serial.println("ClientHello bytes:");

  printHex(clientHello, clientHelloLength);


  // =======================================================
  // SEND CLIENT HELLO
  // =======================================================

  Serial.println();

  Serial.println("Sending ClientHello...");

  size_t sent =
      client.write(clientHello, clientHelloLength);

  Serial.print("Bytes sent: ");
  Serial.println(sent);

  Serial.println("ClientHello sent!");


  // =======================================================
  // WAIT FOR TLS RESPONSE
  // =======================================================

  Serial.println();

  Serial.println("Waiting for TLS response...");

  unsigned long start = millis();
  printMemory();

  while (millis() - start < 15000)
  {
    if (client.available())
    {
      Serial.println();

      Serial.println("Received TLS bytes:");

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
          Serial.println("Could not read TLS record header.");
          break;
        }


        Serial.println();
        Serial.println("=== TLS Record ===");

        Serial.print("Content type: 0x");

        if (contentType < 0x10)
          Serial.print('0');

        Serial.println(contentType, HEX);


        Serial.print("TLS version: ");

        Serial.print(versionMajor);
        Serial.print(".");
        Serial.println(versionMinor);


        Serial.print("Record length: ");
        Serial.println(recordLength);


        // For now, just consume the record payload.
        // We will parse it properly in the next step.

        Serial.println("Payload:");

        for (uint16_t i = 0; i < recordLength; i++)
        {
          while (!client.available())
          {
            if (!client.connected())
              break;

            delay(1);
          }

          if (!client.available())
            break;

          uint8_t b = client.read();

          if (b < 0x10)
            Serial.print('0');

          Serial.print(b, HEX);
          Serial.print(' ');

          if ((i + 1) % 16 == 0)
            Serial.println();
        }

        Serial.println();


        // Don't immediately exit.
        // There can be multiple TLS records.
      }
    }


    if (!client.connected())
    {
      Serial.println();

      Serial.println(
        "TCP connection was closed by server."
      );

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

    Serial.println("TCP connection still open.");
  }
  else
  {
    Serial.println();

    Serial.println("TCP connection closed.");
  }


  client.stop();
}


void loop()
{
}