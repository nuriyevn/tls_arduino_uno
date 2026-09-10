// Dual architecture source.
// X64 TLS implementation is canonical.
// AVR uses the exact same TLS implementation; only the platform/network layer differs.
// Change AVR_ARCH / X64_ARCH to build the other platform.
//
// TLS_VERBOSE_DEBUG:
//   0 = no verbose TLS debug output (default)
//   1 = enable X64 std::printf TLS debug output

#if !defined(AVR_ARCH) && !defined(X64_ARCH)
#define AVR_ARCH
#endif

#if defined(AVR_ARCH) && defined(X64_ARCH)
#error "Define only AVR_ARCH or X64_ARCH"
#endif

#ifndef TLS_VERBOSE_DEBUG
#define TLS_VERBOSE_DEBUG 0
#endif

#if defined(AVR_ARCH)


#include <Arduino.h>
#include <Ethernet.h>
#include <avr/pgmspace.h>
#include "U256.h"
//#include "lcd.h"

#define USE_DNS_LIB
#include <Dns.h>


//#define TURN_LCD_ON 1
#define DEBUG_TLS_ALERTS 0
#define USE_EUCLIDEAN_INVERSE 1
#define TLS_DEBUG_PRINTF(...) do { } while (0)
/*
class SilentSerial
{
public:
    void begin(unsigned long) {}

    template <typename T>
    void print(const T&) {}

    template <typename T, typename U>
    void print(const T&, U) {}

    template <typename T>
    void println(const T&) {}

    void println() {}
};

SilentSerial silentSerial;

#define Serial silentSerial
*/
#elif defined(X64_ARCH)

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

using byte = uint8_t;
using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::int8_t;
using std::int16_t;
using std::int32_t;
using std::uintptr_t;

struct __FlashStringHelper {};
#define F(s) reinterpret_cast<const __FlashStringHelper *>(s)
#define PROGMEM
#define pgm_read_byte(p) (*(const uint8_t *)(p))
#define pgm_read_dword(p) (*(const uint32_t *)(p))
#define HEX 16

struct U256 { uint8_t v[32]; };
#if defined(TLS_VERBOSE_DEBUG) && TLS_VERBOSE_DEBUG
#define TLS_DEBUG_PRINTF(...) std::printf(__VA_ARGS__)
#else
#define TLS_DEBUG_PRINTF(...) do { } while (0)
#endif

static unsigned long millis()
{
    static const auto t0 = std::chrono::steady_clock::now();
    return (unsigned long)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
}

static void delay(unsigned long ms)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

class SerialMock
{
public:
    void begin(unsigned long) {}
    void print(const char *s) { std::fputs(s ? s : "", stdout); }
    void print(const __FlashStringHelper *s) { std::fputs(reinterpret_cast<const char *>(s), stdout); }
    void print(char c) { std::fputc(c, stdout); }
    void print(uint8_t v) { TLS_DEBUG_PRINTF("%u", (unsigned)v); }
    void print(int8_t v) { TLS_DEBUG_PRINTF("%d", (int)v); }
    void print(uint16_t v) { TLS_DEBUG_PRINTF("%u", (unsigned)v); }
    void print(uint32_t v) { TLS_DEBUG_PRINTF("%u", (unsigned)v); }
    void print(uint64_t v) { TLS_DEBUG_PRINTF("%llu", (unsigned long long)v); }
    void print(bool v) { std::fputs(v ? "1" : "0", stdout); }
    void print(uint8_t v, int base) { if (base == HEX) TLS_DEBUG_PRINTF("%02X", (unsigned)v); else print(v); }
    void println() { std::fputc('\n', stdout); }
    void println(const char *s) { print(s); println(); }
    void println(const __FlashStringHelper *s) { print(s); println(); }
    void println(char c) { print(c); println(); }
    void println(uint8_t v) { print(v); println(); }
    void println(int8_t v) { print(v); println(); }
    void println(uint16_t v) { print(v); println(); }
    void println(uint32_t v) { print(v); println(); }
    void println(uint64_t v) { print(v); println(); }
};
static SerialMock Serial;

class IPAddress
{
    uint8_t b[4];
public:
    IPAddress() : b{0,0,0,0} {}
    IPAddress(uint8_t a, uint8_t c, uint8_t d, uint8_t e) : b{a,c,d,e} {}
    uint8_t &operator[](int i) { return b[i]; }
    uint8_t operator[](int i) const { return b[i]; }
    bool operator==(const IPAddress &o) const { return std::memcmp(b, o.b, 4) == 0; }
};

class EthernetClient
{
    int fd_ = -1;

    static bool connectResolved(int &fd, const char *host, uint16_t port)
    {
        char service[6];
        std::snprintf(service, sizeof(service), "%u", (unsigned)port);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo *result = nullptr;
        if (getaddrinfo(host, service, &hints, &result) != 0)
            return false;
        for (addrinfo *rp = result; rp; rp = rp->ai_next)
        {
            int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (s < 0) continue;
            if (::connect(s, rp->ai_addr, rp->ai_addrlen) == 0)
            {
                fd = s;
                freeaddrinfo(result);
                return true;
            }
            close(s);
        }
        freeaddrinfo(result);
        return false;
    }

public:
    EthernetClient() = default;
    EthernetClient(const EthernetClient &) = delete;
    EthernetClient &operator=(const EthernetClient &) = delete;
    ~EthernetClient() { stop(); }

    bool connected() const
    {
        if (fd_ < 0) return false;
        uint8_t b;
        int rc = recv(fd_, &b, 1, MSG_PEEK | MSG_DONTWAIT);
        if (rc > 0) return true;
        if (rc == 0) return false;
        return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
    }

    int available() const
    {
        if (fd_ < 0) return 0;
        int count = 0;
        return ioctl(fd_, FIONREAD, &count) == 0 ? count : 0;
    }

    int read()
    {
        if (fd_ < 0) return -1;
        uint8_t b;
        ssize_t n = recv(fd_, &b, 1, 0);
        return n == 1 ? b : -1;
    }

    size_t write(uint8_t value)
    {
        if (fd_ < 0) return 0;
        ssize_t n;
        do { n = send(fd_, &value, 1, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
        if (n != 1) stop();
        return n == 1 ? 1 : 0;
    }

    size_t write(const uint8_t *data, size_t length)
    {
        if (fd_ < 0) return 0;
        size_t sent = 0;
        while (sent < length)
        {
            ssize_t n = send(fd_, data + sent, length - sent, MSG_NOSIGNAL);
            if (n > 0) { sent += (size_t)n; continue; }
            if (n < 0 && errno == EINTR) continue;
            stop();
            break;
        }
        return sent;
    }

    bool connect(const IPAddress &ip, uint16_t port)
    {
        stop();
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        uint32_t value = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
                         ((uint32_t)ip[2] << 8) | ip[3];
        addr.sin_addr.s_addr = htonl(value);
        fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        if (::connect(fd_, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) != 0)
        {
            stop();
            return false;
        }
        return true;
    }

    bool connect(const char *host, uint16_t port)
    {
        stop();

        TLS_DEBUG_PRINTF("DNS/TCP: %s:%u\n", host, (unsigned)port);

        char service[6];
        std::snprintf(service, sizeof(service), "%u", (unsigned)port);

        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        addrinfo *result = nullptr;

        int rc = getaddrinfo(host, service, &hints, &result);

        if (rc != 0)
        {
            TLS_DEBUG_PRINTF("getaddrinfo: %s\n", gai_strerror(rc));
            return false;
        }

        for (addrinfo *rp = result; rp; rp = rp->ai_next)
        {
            int s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if (s < 0)
            {
                TLS_DEBUG_PRINTF("socket: errno=%d\n", errno);
                continue;
            }

            if (::connect(s, rp->ai_addr, rp->ai_addrlen) == 0)
            {
                fd_ = s;
                freeaddrinfo(result);

                TLS_DEBUG_PRINTF("TCP SOCKET CONNECTED\n");
                return true;
            }

            TLS_DEBUG_PRINTF("connect: errno=%d (%s)\n",
                        errno,
                        std::strerror(errno));

            close(s);
        }

        freeaddrinfo(result);
        return false;
    }

    bool connect(const __FlashStringHelper *host, uint16_t port)
    {
        return connect(reinterpret_cast<const char *>(host), port);
    }

    void stop()
    {
        if (fd_ >= 0)
        {
            shutdown(fd_, SHUT_RDWR);
            close(fd_);
            fd_ = -1;
        }
    }
};

class EthernetUDP
{
public:
    uint8_t begin(uint16_t) { return 1; }
    void beginPacket(const IPAddress&, uint16_t) {}
    size_t write(uint8_t) { return 1; }
    size_t write(char c) { return write((uint8_t)c); }
    void endPacket() {}
    int parsePacket() { return 0; }
    int read(uint8_t *, size_t) { return 0; }
    void stop() {}
};

class DNSClient
{
public:
    void begin(const IPAddress&) {}
    int getHostByName(const char *host, IPAddress &ip)
    {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo *result = nullptr;
        if (getaddrinfo(host, nullptr, &hints, &result) != 0 || !result)
            return 0;
        uint32_t value = ntohl(reinterpret_cast<const sockaddr_in *>(result->ai_addr)->sin_addr.s_addr);
        ip = IPAddress((uint8_t)(value >> 24), (uint8_t)(value >> 16),
                       (uint8_t)(value >> 8), (uint8_t)value);
        freeaddrinfo(result);
        return 1;
    }
};

class EthernetMock
{
public:
    int begin(const uint8_t *) { return 1; }
    IPAddress localIP() const { return IPAddress(127,0,0,1); }
    IPAddress gatewayIP() const { return IPAddress(127,0,0,1); }
    IPAddress dnsServerIP() const { return IPAddress(127,0,0,1); }
};

static EthernetMock Ethernet;

char __heap_start;
char *__brkval = nullptr;


#define DEBUG_TLS_ALERTS 0
#define USE_EUCLIDEAN_INVERSE 1
#endif

struct GCM128;
struct SHA256Context;
struct Point;
struct PointProjective;

static void gcmInit(GCM128 &ctx, const uint8_t key[16]);
static void gcmHashBlock(GCM128 &ctx, const uint8_t block[16]);
void sha256Init(SHA256Context &ctx);
void sha256UpdateByte(SHA256Context &ctx, uint8_t value);
void sha256Final(SHA256Context &ctx, uint8_t digest[32]);
uint8_t primeByte256(int i);
bool isZero256(const U256 &a);
void tlsPrfSha256(const uint8_t *secret, uint8_t secretLength, const uint8_t *label, uint8_t labelLength, const uint8_t *seed, uint8_t seedLength, uint8_t *output, uint8_t *output2, uint16_t outputLength);

bool networkConnect();

struct GCM128
{
    uint8_t H[16];   // Hash subkey
    uint8_t Y[16];   // GHASH accumulator
};
EthernetClient client;
#define TLS_SOCKET 0

struct Point
{
  U256 x;
  U256 y;
};
const byte mac[] PROGMEM = {
  //0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
  0x02, 0x12, 0x34, 0x56, 0x78, 0x9A
};

struct SHA256Context
{
    uint32_t state[8];
    uint64_t bitCount;
    uint8_t buffer[64];
};

const uint8_t aesSBox[256] PROGMEM =
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
uint8_t aesRoundKey[16];
uint8_t aesXtime(uint8_t value)
{
    return (uint8_t)(
        (value << 1) ^
        ((value & 0x80) ? 0x1B : 0x00)
    );
}


void aesAddRoundKey(    uint8_t block[16],    const uint8_t roundKey[16])
{
    for (uint8_t i = 0; i < 16; i++)
        block[i] ^= roundKey[i];
}

void aesSubBytes(uint8_t block[16])
{
    for (uint8_t i = 0; i < 16; i++)
        block[i] =
            pgm_read_byte(&aesSBox[block[i]]);
}

void aesShiftRows(uint8_t block[16])
{
    uint8_t temp;

    // Row 1: left rotate by 1.
    temp = block[1];
    block[1]  = block[5];
    block[5]  = block[9];
    block[9]  = block[13];
    block[13] = temp;

    // Row 2: left rotate by 2.
    temp = block[2];
    block[2]  = block[10];
    block[10] = temp;

    temp = block[6];
    block[6]  = block[14];
    block[14] = temp;

    // Row 3: left rotate by 3.
    temp = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7]  = block[3];
    block[3]  = temp;
}

void aesMixColumns(uint8_t block[16])
{
    for (uint8_t i = 0; i < 16; i += 4)
    {
        uint8_t a = block[i];
        uint8_t b = block[i + 1];
        uint8_t c = block[i + 2];
        uint8_t d = block[i + 3];

        uint8_t ab = aesXtime(a);
        uint8_t bc = aesXtime(b);
        uint8_t cc = aesXtime(c);
        uint8_t dc = aesXtime(d);

        block[i] =
            ab ^ (bc ^ b) ^ c ^ d;

        block[i + 1] =
            a ^ bc ^ (cc ^ c) ^ d;

        block[i + 2] =
            a ^ b ^ cc ^ (dc ^ d);

        block[i + 3] =
            (ab ^ a) ^ b ^ c ^ dc;
    }
}

void aesExpandRoundKey(    uint8_t roundKey[16],    uint8_t round)
{
    uint8_t t0 = roundKey[13];
    uint8_t t1 = roundKey[14];
    uint8_t t2 = roundKey[15];
    uint8_t t3 = roundKey[12];

    t0 = pgm_read_byte(&aesSBox[t0]);
    t1 = pgm_read_byte(&aesSBox[t1]);
    t2 = pgm_read_byte(&aesSBox[t2]);
    t3 = pgm_read_byte(&aesSBox[t3]);

    uint8_t rcon = 1;

    for (uint8_t i = 1; i < round; i++)
        rcon = aesXtime(rcon);

    t0 ^= rcon;

    roundKey[0] ^= t0;
    roundKey[1] ^= t1;
    roundKey[2] ^= t2;
    roundKey[3] ^= t3;

    for (uint8_t i = 4; i < 16; i++)
        roundKey[i] ^= roundKey[i - 4];
}

void aes128EncryptBlock(    const uint8_t key[16],    uint8_t block[16])
{
    // Serial.print(F("FREE SRAM BEFORE AES: "));
    // Serial.println(getFreeMemory());

    for (uint8_t i = 0; i < 16; i++)
        aesRoundKey[i] = key[i];

    // Round 0.
    aesAddRoundKey(block, aesRoundKey);

    // Rounds 1..9.
    for (uint8_t round = 1; round <= 9; round++)
    {
        aesExpandRoundKey(aesRoundKey, round);

        aesSubBytes(block);
        aesShiftRows(block);
        aesMixColumns(block);
        aesAddRoundKey(block, aesRoundKey);
    }

    // Round 10.
    aesExpandRoundKey(aesRoundKey, 10);

    aesSubBytes(block);
    aesShiftRows(block);
    aesAddRoundKey(block, aesRoundKey);
}

// =======================================================
// AES-GCM — GHASH
// =======================================================


uint8_t gcmV[16];

// X = X * H in GF(2^128)
static void gcmMultiply(    uint8_t result[16],    const uint8_t X[16],    const uint8_t H[16])
{
    for (uint8_t i = 0; i < 16; i++)
    {
        result[i] = 0;
        gcmV[i] = H[i];
    }

    for (uint8_t i = 0; i < 128; i++)
    {
        uint8_t bit =
            (X[i >> 3] >> (7 - (i & 7))) & 1;

        if (bit)
        {
            for (uint8_t j = 0; j < 16; j++)
                result[j] ^= gcmV[j];
        }

        uint8_t lsb = gcmV[15] & 1;

        for (int8_t j = 15; j > 0; j--)
        {
            gcmV[j] =
                (uint8_t)((gcmV[j] >> 1) |
                          (gcmV[j - 1] << 7));
        }

        gcmV[0] >>= 1;

        if (lsb)
            gcmV[0] ^= 0xE1;
    }
}

static void gcmXorBlock(    uint8_t dst[16],    const uint8_t src[16])
{
    for (uint8_t i = 0; i < 16; i++)
        dst[i] ^= src[i];
}

static void gcmInit(    GCM128 &ctx,    const uint8_t key[16])
{
    uint8_t zero[16] = {0};

    // H = AES_K(0^128)
    aes128EncryptBlock(key, zero);

    for (uint8_t i = 0; i < 16; i++)
        ctx.H[i] = zero[i];

    for (uint8_t i = 0; i < 16; i++)
        ctx.Y[i] = 0;
}


static void gcmHashBlock(    GCM128 &ctx,    const uint8_t block[16])
{
    gcmXorBlock(ctx.Y, block);

    uint8_t product[16];

    gcmMultiply(
        product,
        ctx.Y,
        ctx.H
    );

    for (uint8_t i = 0; i < 16; i++)
        ctx.Y[i] = product[i];
}

static void gcmIncrementCounter(uint8_t counter[16])
{
    for (int8_t i = 15; i >= 12; i--)
    {
        counter[i]++;

        if (counter[i] != 0)
            break;
    }
}

static void tlsGcmMakeNonce(    uint8_t nonce[12],    const uint8_t fixedIV[4],    uint64_t sequenceNumber)
{
    // TLS 1.2 AES-GCM nonce:
    // fixed IV (4 bytes) || sequence number (8 bytes)

    nonce[0] = fixedIV[0];
    nonce[1] = fixedIV[1];
    nonce[2] = fixedIV[2];
    nonce[3] = fixedIV[3];

    nonce[4]  = (uint8_t)(sequenceNumber >> 56);
    nonce[5]  = (uint8_t)(sequenceNumber >> 48);
    nonce[6]  = (uint8_t)(sequenceNumber >> 40);
    nonce[7]  = (uint8_t)(sequenceNumber >> 32);
    nonce[8]  = (uint8_t)(sequenceNumber >> 24);
    nonce[9]  = (uint8_t)(sequenceNumber >> 16);
    nonce[10] = (uint8_t)(sequenceNumber >> 8);
    nonce[11] = (uint8_t)(sequenceNumber);
}

static void tlsGcmMakeJ0(    uint8_t J0[16],    const uint8_t nonce[12])
{
    for (uint8_t i = 0; i < 12; i++)
        J0[i] = nonce[i];

    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;
}

static void tlsGcmMakeAAD(    uint8_t aad[13],    uint64_t sequenceNumber,    uint8_t contentType,
    uint8_t versionMajor,    uint8_t versionMinor,    uint16_t plaintextLength)
{
    // 8-byte TLS record sequence number
    aad[0] = (uint8_t)(sequenceNumber >> 56);
    aad[1] = (uint8_t)(sequenceNumber >> 48);
    aad[2] = (uint8_t)(sequenceNumber >> 40);
    aad[3] = (uint8_t)(sequenceNumber >> 32);
    aad[4] = (uint8_t)(sequenceNumber >> 24);
    aad[5] = (uint8_t)(sequenceNumber >> 16);
    aad[6] = (uint8_t)(sequenceNumber >> 8);
    aad[7] = (uint8_t)sequenceNumber;

    // TLS record header fields
    aad[8]  = contentType;
    aad[9]  = versionMajor;
    aad[10] = versionMinor;

    aad[11] = (uint8_t)(plaintextLength >> 8);
    aad[12] = (uint8_t)plaintextLength;
}

static bool tlsSendChangeCipherSpec()
{
    if (client.write((uint8_t)0x14) != 1) return false;
    if (client.write((uint8_t)0x03) != 1) return false;
    if (client.write((uint8_t)0x03) != 1) return false;

    if (client.write((uint8_t)0x00) != 1) return false;
    if (client.write((uint8_t)0x01) != 1) return false;

    if (client.write((uint8_t)0x01) != 1) return false;

    return true;
}

static void gcmCtrCrypt(const uint8_t key[16], uint8_t counter[16],uint8_t *data,  uint16_t length)
{
    uint8_t stream[16];

    while (length)
    {
        for (uint8_t i = 0; i < 16; i++)
            stream[i] = counter[i];

        // Serial.print(F("CTR="));
        // for (uint8_t i = 0; i < 16; i++)
        // {
        //     if (stream[i] < 16) Serial.print('0');
        //     Serial.print(stream[i], HEX);
        // }
        // Serial.println();

        aes128EncryptBlock(key, stream);

        // Serial.print(F("KS="));
        // for (uint8_t i = 0; i < 16; i++)
        // {
        //     if (stream[i] < 16) Serial.print('0');
        //     Serial.print(stream[i], HEX);
        // }
        // Serial.println();

        uint8_t n = (length < 16) ? length : 16;

        for (uint8_t i = 0; i < n; i++)
            data[i] ^= stream[i];

        data += n;
        length -= n;

        gcmIncrementCounter(counter);
    }
}

static void gcmMakeTag(    const uint8_t key[16],    const uint8_t J0[16],    const uint8_t *aad,    uint16_t aadLen,
    const uint8_t *ciphertext,    uint16_t ciphertextLen,    uint8_t tag[16])
{

    // Serial.print(F("FREE SRAM ENTER gcmMakeTag: "));
    // Serial.println(getFreeMemory());
    GCM128 ctx;
    gcmInit(ctx, key);;

    uint8_t work[16];

    uint16_t originalAadLen = aadLen;
    uint16_t originalCiphertextLen = ciphertextLen;

    // AAD
    while (aadLen >= 16)
    {
        gcmHashBlock(ctx, aad);
        aad += 16;
        aadLen -= 16;
    }

    if (aadLen)
    {
        for (uint8_t i = 0; i < 16; i++)
            work[i] = 0;

        for (uint8_t i = 0; i < aadLen; i++)
            work[i] = aad[i];

        gcmHashBlock(ctx, work);

    }

    // Ciphertext
    while (ciphertextLen >= 16)
    {
        gcmHashBlock(ctx, ciphertext);

        ciphertext += 16;
        ciphertextLen -= 16;
    }

    if (ciphertextLen)
    {
        for (uint8_t i = 0; i < 16; i++)
            work[i] = 0;

        for (uint8_t i = 0; i < ciphertextLen; i++)
            work[i] = ciphertext[i];

        gcmHashBlock(ctx, work);
    }

    // Length block
    for (uint8_t i = 0; i < 16; i++)
        work[i] = 0;
    uint32_t aadBits =
        (uint32_t)originalAadLen * 8UL;

    uint32_t ciphertextBits =
        (uint32_t)originalCiphertextLen * 8UL;

    work[4] = aadBits >> 24;
    work[5] = aadBits >> 16;
    work[6] = aadBits >> 8;
    work[7] = aadBits;

    work[12] = ciphertextBits >> 24;
    work[13] = ciphertextBits >> 16;
    work[14] = ciphertextBits >> 8;
    work[15] = ciphertextBits;

    gcmHashBlock(ctx, work);



    // Tag = AES(K, J0) XOR GHASH
    for (uint8_t i = 0; i < 16; i++)
        work[i] = J0[i];

    aes128EncryptBlock(key, work);

    for (uint8_t i = 0; i < 16; i++)
        tag[i] = work[i] ^ ctx.Y[i];
}

const uint8_t aesTestKey[16] PROGMEM =
{
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};

const uint8_t aesTestPlaintext[16] PROGMEM =
{
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB,
    0xCC, 0xDD, 0xEE, 0xFF
};


uint8_t serverRandom[32];
uint8_t tlsMasterSecret[48];
uint8_t clientWriteKey[16];
uint8_t clientWriteIV[4];
uint8_t clientRandom[32];
uint8_t serverWriteKey[16];
uint8_t serverWriteIV[4];

struct ECCWorkspace
{
  Point point1;
  // Point point2; //optimized out

  U256 temp1;
  U256 temp2;
  U256 temp3;
  U256 temp4;
  uint8_t product[64]; // this is used also for  savedSeed  inside of tlsPrfSha256
};

struct PointProjective
{
  U256 x;
  U256 y;
  U256 z;
};

ECCWorkspace ecc;

#define ecdheSharedSecret ecc.temp1
#define tlsPrfA ecc.temp2.v

uint8_t tlsKeyBlock[40]; // TODO  temporaroly added because temp3 is 32 bytes we need 40
// actually we can use somehow both of them.


uint8_t tlsPrfInput[109];
uint8_t tlsHmacKeyBlock[64];
uint8_t tlsHmacInnerHash[32];
SHA256Context tlsHmacContext;
bool tlsTranscriptRecord = false;
uint64_t tlsWriteSequence = 0;
uint64_t tlsReadSequence = 0;

void tlsTranscriptInit()
{
    sha256Init(tlsHmacContext);
}

void tlsTranscriptUpdateByte(uint8_t value)
{   
    sha256UpdateByte(tlsHmacContext, value);
}
void printHex(
    const __FlashStringHelper *label,
    const uint8_t *data,
    uint8_t length,
    bool reverse = false)
{
    Serial.print(label);

    if (reverse)
    {
        for (int16_t i = (int16_t)length - 1; i >= 0; i--)
        {
            if (data[i] < 16)
                Serial.print('0');

            Serial.print(data[i], HEX);
        }
    }
    else
    {
        for (uint8_t i = 0; i < length; i++)
        {
            if (data[i] < 16)
                Serial.print('0');

            Serial.print(data[i], HEX);
        }
    }

    Serial.println();
}

void tlsTranscriptFinal(uint8_t digest[32])
{
    // Save SHA-256 context so we can continue the transcript later.

    // Save state[8] = 32 bytes
    for (uint8_t i = 0; i < 8; i++)
    {
        tlsHmacInnerHash[i * 4]     = (uint8_t)(tlsHmacContext.state[i] >> 24);
        tlsHmacInnerHash[i * 4 + 1] = (uint8_t)(tlsHmacContext.state[i] >> 16);
        tlsHmacInnerHash[i * 4 + 2] = (uint8_t)(tlsHmacContext.state[i] >> 8);
        tlsHmacInnerHash[i * 4 + 3] = (uint8_t)tlsHmacContext.state[i];
    }

    // Save bitCount = 8 bytes
    uint64_t savedBitCount = tlsHmacContext.bitCount;

    // Save buffered data = 64 bytes
    for (uint8_t i = 0; i < 64; i++)
        tlsHmacKeyBlock[i]  = tlsHmacContext.buffer[i];

    // Finalize to produce the digest.
    sha256Final(tlsHmacContext, digest);

    // Restore state[8].
    for (uint8_t i = 0; i < 8; i++)
    {
        tlsHmacContext.state[i] =
            ((uint32_t)tlsHmacInnerHash[i * 4] << 24) |
            ((uint32_t)tlsHmacInnerHash[i * 4 + 1] << 16) |
            ((uint32_t)tlsHmacInnerHash[i * 4 + 2] << 8) |
            ((uint32_t)tlsHmacInnerHash[i * 4 + 3]);
    }

    // Restore bitCount.
    tlsHmacContext.bitCount = savedBitCount;

    // Restore buffered data.
    for (uint8_t i = 0; i < 64; i++)
        tlsHmacContext.buffer[i] = tlsHmacKeyBlock[i];
}


static bool tlsSendGCMRecord(    uint8_t contentType,    uint8_t *plaintext,    uint16_t plaintextLength)
{
    // Serial.print(F("CONNECTED GCM START: "));
    // Serial.println(client.connected());
    // Serial.print(F("FREE SRAM GCM START: "));
    // Serial.println(getFreeMemory());


    
    uint8_t J0[16];
    uint8_t counter[16];
    uint8_t aad[13];

    // --------------------------------------------------
    // Nonce = client_write_IV || sequence_number
    // --------------------------------------------------
    J0[0] = clientWriteIV[0];
    J0[1] = clientWriteIV[1];
    J0[2] = clientWriteIV[2];
    J0[3] = clientWriteIV[3];

    J0[4]  = (uint8_t)(tlsWriteSequence >> 56);
    J0[5]  = (uint8_t)(tlsWriteSequence >> 48);
    J0[6]  = (uint8_t)(tlsWriteSequence >> 40);
    J0[7]  = (uint8_t)(tlsWriteSequence >> 32);
    J0[8]  = (uint8_t)(tlsWriteSequence >> 24);
    J0[9]  = (uint8_t)(tlsWriteSequence >> 16);
    J0[10] = (uint8_t)(tlsWriteSequence >> 8);
    J0[11] = (uint8_t)tlsWriteSequence;

    J0[12] = 0;
    J0[13] = 0;
    J0[14] = 0;
    J0[15] = 1;
    printHex(F("J0="), J0, 16);
     Serial.print("SEQ=");
     Serial.println((unsigned long)tlsWriteSequence);

    // Serial.print("J0=");
    // for (uint8_t i = 0; i < 16; i++)
    // {
    //     if (J0[i] < 16) Serial.print('0');
    //     Serial.print(J0[i], HEX);
    // }
    // Serial.println();


    // --------------------------------------------------
    // TLS AAD:
    //
    // sequence_number
    // content_type
    // version
    // plaintext_length
    // --------------------------------------------------

    aad[0] = (uint8_t)(tlsWriteSequence >> 56);
    aad[1] = (uint8_t)(tlsWriteSequence >> 48);
    aad[2] = (uint8_t)(tlsWriteSequence >> 40);
    aad[3] = (uint8_t)(tlsWriteSequence >> 32);
    aad[4] = (uint8_t)(tlsWriteSequence >> 24);
    aad[5] = (uint8_t)(tlsWriteSequence >> 16);
    aad[6] = (uint8_t)(tlsWriteSequence >> 8);
    aad[7] = (uint8_t)(tlsWriteSequence);

    aad[8]  = contentType;
    aad[9]  = 0x03;
    aad[10] = 0x03;

    aad[11] = (uint8_t)(plaintextLength >> 8);
    aad[12] = (uint8_t)(plaintextLength);

    // --------------------------------------------------
    // Counter = inc32(J0)
    // --------------------------------------------------
    printHex(F("AAD="), aad, 13);
    for (uint8_t i = 0; i < 16; i++)
        counter[i] = J0[i];

    gcmIncrementCounter(counter);

    // --------------------------------------------------
    // Encrypt plaintext IN PLACE
    // --------------------------------------------------
    // Serial.print(F("SRAM BEFORE CTR: "));
    // Serial.println(getFreeMemory());
    gcmCtrCrypt(
        clientWriteKey,
        counter,
        plaintext,
        plaintextLength
    );

    // Serial.print(F("SRAM AFTER CTR: "));
    // Serial.println(getFreeMemory());
    // --------------------------------------------------
    // Authentication tag
    // --------------------------------------------------
    // Serial.print(F("SRAM BEFORE TAG: "));
    // Serial.println(getFreeMemory());
    gcmMakeTag(
        clientWriteKey,
        J0,
        aad,
        13,
        plaintext,
        plaintextLength,
        counter
    );

    
    // Serial.print("CT=");
    // for (uint8_t i = 0; i < plaintextLength; i++)
    // {
    //     if (plaintext[i] < 16) Serial.print('0');
    //     Serial.print(plaintext[i], HEX);
    // }
    // Serial.println();

    // Serial.print("TAG=");
    // for (uint8_t i = 0; i < 16; i++)
    // {
    //     if (counter[i] < 16) Serial.print('0');
    //     Serial.print(counter[i], HEX);
    // }
    // Serial.println();
    // Serial.print(F("SRAM AFTER TAG: "));
    // Serial.println(getFreeMemory());
    // Serial.print(F("CONNECTED AFTER GCM COMPUTE: "));
    // Serial.println(client.connected());

    // --------------------------------------------------
    // TLS record length:
    //
    // explicit nonce = 8
    // ciphertext     = plaintextLength
    // authentication tag = 16
    // --------------------------------------------------

    uint16_t recordLength =
        8 + plaintextLength + 16;

    // --------------------------------------------------
    // TLS record header
    // --------------------------------------------------
    // Serial.print(F("CONNECTED BEFORE AVAILABLE: "));
    // Serial.println(client.connected());
    // Serial.print(F("AVAILABLE BEFORE GCM: "));
    // Serial.println(client.available());
    // Serial.print(F("CONNECTED BEFORE GCM: "));
    // Serial.println(client.connected());
    if (!client.connected())
    {
        // showStage(202);
        return false;
    }

    if (client.write(contentType) != 1) return false;
    if (client.write((uint8_t)0x03) != 1) return false;
    if (client.write((uint8_t)0x03) != 1) return false;
    if (client.write((uint8_t)(recordLength >> 8)) != 1) return false;
    if (client.write((uint8_t)recordLength) != 1) return false;

    // --------------------------------------------------
    // Explicit nonce = sequence number
    // --------------------------------------------------

    for (int8_t i = 7; i >= 0; i--)
    {
        if (client.write(
                (uint8_t)(tlsWriteSequence >> (i * 8))
            ) != 1)
        {
            // Serial.println(F("GCM NONCE WRITE FAIL"));
            return false;
        }
    }


    // --------------------------------------------------
    // Ciphertext
    // --------------------------------------------------

    for (uint16_t i = 0; i < plaintextLength; i++)
    {
        if (client.write(plaintext[i]) != 1)
        {
            // Serial.println(F("GCM CIPHERTEXT WRITE FAIL"));
            return false;
        }
    }

    // --------------------------------------------------
    // Authentication tag
    // --------------------------------------------------

    for (uint8_t i = 0; i < 16; i++)
    {
        if (client.write(counter[i]) != 1)
        {
            // Serial.println(F("GCM AUTHENTICATION TAG WRITE FAIL"));
            return false;
        }
    }


    // --------------------------------------------------
    // Next encrypted record
    // --------------------------------------------------

    tlsWriteSequence++;

    return true;
}

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

void fromBigEndianProgmem(U256 &result, const uint8_t *data)
{
  for (int i = 0; i < 32; i++)
  {
    result.v[i] = pgm_read_byte(&data[31 - i]);
  }
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

int comparePrime256(const U256 &a);
void subtractPrime256(U256 &result);

void modAdd256(U256 &result, const U256 &a, const U256 &b)
{
  uint8_t carry = add256(result, a, b);

  // A carry means the full sum exceeded 2^256. Since p is less than
  // 2^256, both that case and result >= p require one reduction.
  if (carry || comparePrime256(result) >= 0)
    subtractPrime256(result);
}
void modSub256(U256 &result, const U256 &a, const U256 &b)
{
  if (compare256(a, b) >= 0)
  {
    sub256(result, a, b);
    return;
  }

  // a < b:
  // result = a - b + p
  //
  // sub256 wraps at 2^256, so adding p directly
  // produces the correct result modulo p.
  sub256(result, a, b);

  uint8_t carry = 0;

  for (int i = 0; i < 32; i++)
  {
    uint16_t sum =
        (uint16_t)result.v[i] +
        primeByte256(i) +
        carry;

    result.v[i] = (uint8_t)sum;
    carry = (uint8_t)(sum >> 8);
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
uint32_t sha256ScheduleWord(    SHA256Context &ctx,    uint8_t index)
{
    uint8_t j = (index & 15) * 4;

    return
        ((uint32_t)ctx.buffer[j] << 24) |
        ((uint32_t)ctx.buffer[j + 1] << 16) |
        ((uint32_t)ctx.buffer[j + 2] << 8) |
        ((uint32_t)ctx.buffer[j + 3]);
}

void sha256Transform(SHA256Context &ctx)
{
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
        uint32_t wi;

        if (i < 16)
        {
            wi = sha256ScheduleWord(ctx, i);
        }
        else
        {
            uint32_t value =
                sha256SmallSigma1(
                    sha256ScheduleWord(ctx, (i - 2) & 15)
                ) +
                sha256ScheduleWord(ctx, (i - 7) & 15) +
                sha256SmallSigma0(
                    sha256ScheduleWord(ctx, (i - 15) & 15)
                ) +
                sha256ScheduleWord(ctx, i & 15);

            uint8_t j = (i & 15) * 4;

            ctx.buffer[j]     = (uint8_t)(value >> 24);
            ctx.buffer[j + 1] = (uint8_t)(value >> 16);
            ctx.buffer[j + 2] = (uint8_t)(value >> 8);
            ctx.buffer[j + 3] = (uint8_t)value;

            wi = value;
        }

        uint32_t k = pgm_read_dword(&SHA256_K[i]);

        uint32_t t1 =
            h +
            sha256BigSigma1(e) +
            sha256Ch(e, f, g) +
            k +
            wi;

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

void sha256Update(    SHA256Context &ctx,    const uint8_t *data,    uint16_t length)
{
  uint16_t index =
      (uint16_t)((ctx.bitCount >> 3) & 0x3F);

  ctx.bitCount += (uint64_t)length * 8;

  for (uint16_t i = 0; i < length; i++)
  {
    ctx.buffer[index++] = data[i];

    if (index == 64)
    {
      sha256Transform(ctx);
      index = 0;
    }
  }
}

void sha256UpdateByte(    SHA256Context &ctx,    uint8_t value)
{
  sha256Update(ctx, &value, 1);
}

void sha256Final(    SHA256Context &ctx,    uint8_t digest[32])
{
  uint16_t index =
      (uint16_t)((ctx.bitCount >> 3) & 0x3F);

  ctx.buffer[index++] = 0x80;

  if (index > 56)
  {
    while (index < 64)
      ctx.buffer[index++] = 0;

    sha256Transform(ctx);
    index = 0;
  }

  while (index < 56)
    ctx.buffer[index++] = 0;

  uint64_t bits = ctx.bitCount;

  for (int i = 7; i >= 0; i--)
  {
    ctx.buffer[index++] = (uint8_t)(bits >> (i * 8));
  }

  sha256Transform(ctx);

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


void hmacSha256(    const uint8_t *key,    uint8_t keyLength,    const uint8_t *data,    uint16_t dataLength,    uint8_t output[32])
{
    for (uint8_t i = 0; i < 64; i++)
        tlsHmacKeyBlock[i] = 0;

    if (keyLength > 64)
    {
        sha256Init(tlsHmacContext);
        sha256Update(
            tlsHmacContext,
            key,
            keyLength
        );
        sha256Final(
            tlsHmacContext,
            tlsHmacInnerHash
        );

        for (uint8_t i = 0; i < 32; i++)
            tlsHmacKeyBlock[i] =
                tlsHmacInnerHash[i];
    }
    else
    {
        for (uint8_t i = 0; i < keyLength; i++)
            tlsHmacKeyBlock[i] = key[i];
    }

    // H(K) XOR ipad
    for (uint8_t i = 0; i < 64; i++)
        tlsHmacKeyBlock[i] ^= 0x36;

    sha256Init(tlsHmacContext);

    sha256Update(
        tlsHmacContext,
        tlsHmacKeyBlock,
        64
    );

    sha256Update(
        tlsHmacContext,
        data,
        dataLength
    );

    sha256Final(
        tlsHmacContext,
        tlsHmacInnerHash
    );

    // Convert ipad into opad.
    for (uint8_t i = 0; i < 64; i++)
        tlsHmacKeyBlock[i] ^= 0x36 ^ 0x5C;

    sha256Init(tlsHmacContext);

    sha256Update(
        tlsHmacContext,
        tlsHmacKeyBlock,
        64
    );

    sha256Update(
        tlsHmacContext,
        tlsHmacInnerHash,
        32
    );

    sha256Final(
        tlsHmacContext,
        output
    );
}
void printHex(
    const char *label,
    const uint8_t *data,
    uint8_t length,
    bool reverse = false)
{
    if (reverse)
    {
        for (int16_t i = (int16_t)length - 1; i >= 0; i--)
        {
            if (data[i] < 16)
                Serial.print('0');

            Serial.print(data[i], HEX);
        }
    }
    else
    {
        for (uint8_t i = 0; i < length; i++)
        {
            if (data[i] < 16)
                Serial.print('0');

            Serial.print(data[i], HEX);
        }
    }

    Serial.println();
}


void deriveTLSKeys()
{
    // ============================================================
    // ECDHE SHARED SECRET
    // Internal U256 is little-endian.
    // Print in big-endian / TLS byte order.
    // ============================================================
    printHex(
        F("ECDHE_RAW="),
        ecdheSharedSecret.v,
        32,
        true
    );

    // ============================================================
    // MASTER SECRET SEED
    // client_random || server_random
    // ============================================================

    for (uint8_t i = 0; i < 32; i++)
    {
        tlsHmacKeyBlock[i] =
            clientRandom[i];

        tlsHmacKeyBlock[32 + i] =
            serverRandom[i];
    }

    // printHex(        F("CLIENT_RANDOM="),        clientRandom,        32    );
    // printHex(        F("SERVER_RANDOM="),        serverRandom,        32    );
    // printHex(        F("MASTER_SEED="),        tlsHmacKeyBlock,        64    );

    // ============================================================
    // Convert ECDHE shared secret from internal little-endian
    // representation to TLS big-endian representation.
    // ============================================================
    // NOTE: ecdheSharedSecret aliases ecc.temp1,
    // so this reversal converts temp1 from little-endian to TLS big-endian form.

    for (uint8_t i = 0; i < 16; i++)
    {
        uint8_t t =
            ecdheSharedSecret.v[i];

        ecdheSharedSecret.v[i] =
            ecdheSharedSecret.v[31 - i];

        ecdheSharedSecret.v[31 - i] =
            t;
    }







    // ============================================================
    // MASTER SECRET
    // PRF(
    //     ECDHE shared secret,
    //     "master secret",
    //     client_random || server_random
    // )
    // ============================================================

    const uint8_t masterLabel[] PROGMEM =
        "master secret";

    tlsPrfSha256(
        ecdheSharedSecret.v,
        32,
        masterLabel,
        13,
        tlsHmacKeyBlock,
        64,
        tlsMasterSecret,
        nullptr,
        48
    );


    // ============================================================
    // KEY EXPANSION SEED
    // server_random || client_random
    // ============================================================

    for (uint8_t i = 0; i < 32; i++)
    {
        tlsHmacKeyBlock[i] =
            serverRandom[i];

        tlsHmacKeyBlock[32 + i] =
            clientRandom[i];
    }

    //printHex(        F("KEY_EXPANSION_SEED="),        tlsHmacKeyBlock,        64    );

    // ============================================================
    // KEY BLOCK
    //
    // 0..15   client_write_key
    // 16..31  server_write_key
    // 32..35  client_write_IV
    // 36..39  server_write_IV
    // ============================================================

    const uint8_t keyLabel[] PROGMEM =
        "key expansion";

    tlsPrfSha256(
        tlsMasterSecret,
        48,
        keyLabel,
        13,
        tlsHmacKeyBlock,
        64,
        ecc.temp3.v,
        ecc.temp4.v,
        40
        );

    // ============================================================
    // CLIENT WRITE KEY
    // ============================================================

    for (uint8_t i = 0; i < 16; i++)
        clientWriteKey[i] =
            ecc.temp3.v[i];



    // ============================================================
    // SERVER WRITE KEY
    // ============================================================

    for (uint8_t i = 0; i < 16; i++)
        serverWriteKey[i] =
            ecc.temp3.v[16 + i];

    // ============================================================
    // CLIENT WRITE IV
    // ============================================================

    for (uint8_t i = 0; i < 4; i++)
        clientWriteIV[i] =
            ecc.temp4.v[i];


    // ============================================================
    // SERVER WRITE IV
    // ============================================================

    for (uint8_t i = 0; i < 4; i++)
    serverWriteIV[i] =
        ecc.temp4.v[4 + i];
    //printHex(        F("SERVER_WRITE_IV="),        serverWriteIV,        4    );
}


Point ecdheClientPublic;
PointProjective ecdhePoint;
U256 ecdhePrivate;

void modMul256(U256 &result, const U256 &a, const U256 &b)
{
    // modMulCount++;
    // uint16_t freeMemory = getFreeMemory();
    // if (freeMemory < minFreeMemory)
    //     minFreeMemory = freeMemory;

    // 256 x 256 -> 512 bits
    for (uint8_t i = 0; i < 64; i++)
        ecc.product[i] = 0;

    // Schoolbook multiplication
    for (uint8_t i = 0; i < 32; i++)
    {
        uint16_t carry = 0;

        for (uint8_t j = 0; j < 32; j++)
        {
            uint16_t t =
                ecc.product[i + j] +
                (uint16_t)a.v[i] * b.v[j] +
                carry;

            ecc.product[i + j] = (uint8_t)t;
            carry = t >> 8;
        }

        uint8_t k = i + 32;

        while (carry && k < 64)
        {
            uint16_t t = ecc.product[k] + carry;
            ecc.product[k] = (uint8_t)t;
            carry = t >> 8;
            k++;
        }
    }

    // P-256:
    // 2^256 = 2^224 - 2^192 - 2^96 + 1 (mod P)
    for (int8_t k = 63; k >= 32; k--)
    {
        uint8_t c = ecc.product[k];
        ecc.product[k] = 0;

        uint8_t base = k - 32;

        // + c * 2^(base + 224)
        uint16_t carry = c;
        uint8_t pos = base + 28;

        while (carry)
        {
            uint16_t t = ecc.product[pos] + carry;
            ecc.product[pos] = (uint8_t)t;
            carry = t >> 8;
            pos++;
        }

        // + c * 2^base
        carry = c;
        pos = base;

        while (carry)
        {
            uint16_t t = ecc.product[pos] + carry;
            ecc.product[pos] = (uint8_t)t;
            carry = t >> 8;
            pos++;
        }

        // - c * 2^(base + 192)
        uint16_t borrow = c;
        pos = base + 24;

        while (borrow)
        {
            int16_t t = (int16_t)ecc.product[pos] - borrow;

            if (t < 0)
            {
                ecc.product[pos] = (uint8_t)(t + 256);
                borrow = 1;
            }
            else
            {
                ecc.product[pos] = (uint8_t)t;
                borrow = 0;
            }

            pos++;
        }

        // - c * 2^(base + 96)
        borrow = c;
        pos = base + 12;

        while (borrow)
        {
            int16_t t = (int16_t)ecc.product[pos] - borrow;

            if (t < 0)
            {
                ecc.product[pos] = (uint8_t)(t + 256);
                borrow = 1;
            }
            else
            {
                ecc.product[pos] = (uint8_t)t;
                borrow = 0;
            }

            pos++;
        }
    }

    // Copy reduced 256-bit result.
    for (uint8_t i = 0; i < 32; i++)
        result.v[i] = ecc.product[i];

    // Final reduction.
    if (comparePrime256(result) >= 0)
        subtractPrime256(result);
}


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

void printHexPROGMEM(  const uint8_t *buffer,  uint16_t length)
{
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
    {
        sent++;

        // Skip TLS record header; hash handshake bytes only.
        if (i >= 5)
            tlsTranscriptUpdateByte(value);
    }
    else
    {
        break;
    }
  }

  return sent;
}

bool readTLSByte(uint8_t &value)
{
    unsigned long start = millis();

    while (client.available() == 0)
    {
        if (!client.connected())
            return false;

        if (millis() - start >= 15000UL)
            return false;

        delay(1);
    }

    int v = client.read();

    if (v < 0)
        return false;

    value = (uint8_t)v;

    if (tlsTranscriptRecord)
        tlsTranscriptUpdateByte(value);

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


void tlsPrfSha256(
    const uint8_t *secret,
    uint8_t secretLength,
    const uint8_t *label,
    uint8_t labelLength,
    const uint8_t *seed,
    uint8_t seedLength,
    uint8_t *output1,
    uint8_t *output2,
    uint16_t outputLength)
{

    // printHex(F("PRF_SECRET="), secret, secretLength);
    // printHex(F("PRF_LABEL="), label, labelLength);
    // printHex(F("PRF_SEED="), seed, seedLength);
    for (uint8_t i = 0; i < seedLength; i++)
        ecc.product[i] = seed[i];

    uint8_t labelSeedLength = labelLength + seedLength;

    // label + seed
    for (uint8_t i = 0; i < labelLength; i++)
        tlsPrfInput[i] = pgm_read_byte(&label[i]);

    for (uint8_t i = 0; i < seedLength; i++)
        tlsPrfInput[labelLength + i] = ecc.product[i];
    // A(1)
    hmacSha256(
        secret,
        secretLength,
        tlsPrfInput,
        labelSeedLength,
        tlsPrfA
    );
    printHex(        F("PRF_A1="),        tlsPrfA,        32    );
    uint16_t produced = 0;

    while (produced < outputLength)
    {


        // A(i) + label + seed
        for (uint8_t i = 0; i < 32; i++)
            tlsPrfInput[i] = tlsPrfA[i];

        for (uint8_t i = 0; i < labelLength; i++)
            tlsPrfInput[32 + i] = pgm_read_byte(&label[i]);
        for (uint8_t i = 0; i < seedLength; i++)
            tlsPrfInput[32 + labelLength + i] =
                ecc.product[i];
        uint8_t prfBlock[32];
        // P_hash block
        hmacSha256(
            secret,
            secretLength,
            tlsPrfInput,
            32 + labelSeedLength,
            tlsHmacInnerHash
        );
        for (uint8_t i = 0; i < 32; i++)
            prfBlock[i] = tlsHmacInnerHash[i];


        uint16_t remaining = outputLength - produced;
        uint8_t copyLength = remaining < 32 ? remaining : 32;

        if (output2 == nullptr)
        {
            for (uint8_t i = 0; i < copyLength; i++)
                output1[produced + i] = prfBlock[i];
        }
        else
        {
            for (uint8_t i = 0; i < copyLength; i++)
            {
                uint16_t pos = produced + i;

                if (pos < 32)
                    output1[pos] = prfBlock[i];
                else
                    output2[pos - 32] = prfBlock[i];
            }
        }

        //printHex(F("OAC="), output, copyLength>>1);
        produced += copyLength;
        // A(i+1)
        hmacSha256(
            secret,
            secretLength,
            tlsPrfA,
            32,
            tlsPrfA
        );
    }
}


// bool readTLSRecordHeader( uint8_t &contentType, uint8_t &versionMajor, uint8_t &versionMinor, uint16_t &recordLength)
// {
//   unsigned long start = millis();

//   // Wait until the complete 5-byte TLS header is available
//   while (client.available() < 5)
//   {
//     if (!client.connected())
//       return false;

//     if (millis() - start >= 5000)
//       return false;

//     delay(10);
//   }


//   contentType = client.read();
//   versionMajor = client.read();
//   versionMinor = client.read();

//   uint8_t lengthHigh = client.read();
//   uint8_t lengthLow = client.read();

//   recordLength =
//       ((uint16_t)lengthHigh << 8) |
//       lengthLow;

//   return true;
// }
// TEMPORARY
bool readTLSRecordHeader(
    uint8_t &contentType,
    uint8_t &versionMajor,
    uint8_t &versionMinor,
    uint16_t &recordLength)
{
    unsigned long start = millis();

    while (client.available() < 5)
    {
        if (!client.connected())
            return false;

        if (millis() - start >= 5000)
            return false;

        delay(10);
    }

    uint8_t b0 = client.read();
    uint8_t b1 = client.read();
    uint8_t b2 = client.read();
    uint8_t b3 = client.read();
    uint8_t b4 = client.read();
    contentType  = b0;
    versionMajor = b1;
    versionMinor = b2;

    recordLength =
        ((uint16_t)b3 << 8) | b4;
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

void subtractPrime256(U256 &result)
{
  int16_t borrow = 0;

  for (int i = 0; i < 32; i++)
  {
    int16_t value =
        (int16_t)result.v[i] -
        (int16_t)primeByte256(i) -
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
}
#if USE_EUCLIDEAN_INVERSE
bool inverseIsOne256(const U256 &value)
{
  if (value.v[0] != 1)
    return false;

  for (uint8_t i = 1; i < 32; i++)
  {
    if (value.v[i] != 0)
      return false;
  }

  return true;
}

bool inverseIsEven256(const U256 &value)
{
  return (value.v[0] & 1) == 0;
}

void inverseRightShift256(U256 &value)
{
  for (uint8_t i = 0; i < 31; i++)
  {
    value.v[i] =
        (value.v[i] >> 1) |
        (value.v[i + 1] << 7);
  }

  value.v[31] >>= 1;
}

uint8_t inverseAddPrime256(U256 &value)
{
  uint16_t carry = 0;

  for (uint8_t i = 0; i < 32; i++)
  {
    uint16_t sum =
        (uint16_t)value.v[i] +
        primeByte256(i) +
        carry;

    value.v[i] = (uint8_t)sum;
    carry = sum >> 8;
  }

  return (uint8_t)carry;
}

void inverseHalveModPrime256(U256 &value)
{
  if (inverseIsEven256(value))
  {
    inverseRightShift256(value);
    return;
  }

  // Add p before shifting so an odd coefficient becomes even.
  uint8_t carry = inverseAddPrime256(value);

  for (uint8_t i = 0; i < 31; i++)
  {
    value.v[i] =
        (value.v[i] >> 1) |
        (value.v[i + 1] << 7);
  }

  value.v[31] =
      (value.v[31] >> 1) |
      (carry << 7);
}

void modInverse256(U256 &result, const U256 &a)
{
  U256 u;
  U256 v;
  U256 x1;
  U256 x2;

  copy256(u, a);
  fromBigEndianProgmem(v, P256_PRIME_BE);

  zero256(x1);
  x1.v[0] = 1;
  zero256(x2);

  if (isZero256(u))
  {
    zero256(result);
    return;
  }

  while (!inverseIsOne256(u) && !inverseIsOne256(v))
  {
    while (inverseIsEven256(u))
    {
      inverseRightShift256(u);
      inverseHalveModPrime256(x1);
    }

    while (inverseIsEven256(v))
    {
      inverseRightShift256(v);
      inverseHalveModPrime256(x2);
    }

    if (compare256(u, v) >= 0)
    {
      sub256(u, u, v);

      if (compare256(x1, x2) >= 0)
        sub256(x1, x1, x2);
      else
      {
        sub256(x1, x2, x1);
        subPrime256(x1, x1);
      }
    }
    else
    {
      sub256(v, v, u);

      if (compare256(x2, x1) >= 0)
        sub256(x2, x2, x1);
      else
      {
        sub256(x2, x1, x2);
        subPrime256(x2, x2);
      }
    }
  }

  if (inverseIsOne256(u))
    copy256(result, x1);
  else
    copy256(result, x2);
}
#else
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
        modMul256(result, result, a);
      }
    }
  }
}
#endif

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
void __attribute__((noinline)) pointScalarMultiplyProjective(    PointProjective &result,    const U256 &scalar,    const Point &point);
void __attribute__((noinline)) pointScalarMultiplyProjective(    PointProjective &result,    const U256 &scalar,    const Point &point)
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

void __attribute__((noinline)) pointScalarMultiplyGeneratorProjective(
    PointProjective &result,
    const U256 &scalar)
{
    zero256(result.x);
    zero256(result.y);
    zero256(result.z);

    bool started = false;

    for (int8_t byteIndex = 31; byteIndex >= 0; byteIndex--)
    {
        uint8_t value = scalar.v[byteIndex];

        for (int8_t bit = 7; bit >= 0; bit--)
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
/*
void printU256Hex(const U256 &x)
{ for (int8_t i = 31; i >= 0; i--)
    {
        if (x.v[i] < 0x10)
            Serial.print('0');

        Serial.print(x.v[i], HEX);
    }
    {
    Serial.println();}
}*/

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

void testECCMemory()
{
  // modMulCount = 0;

    zero256(ecdhePrivate);

    // Temporary test private scalar = 2.
    ecdhePrivate.v[31] = 0xFF;



    pointScalarMultiplyGeneratorProjective(
        ecdhePoint,
        ecdhePrivate);

    printMemory();

    pointProjectiveToAffine(
        ecdheClientPublic,
        ecdhePoint);

    print256(ecdheClientPublic.x);
    print256(ecdheClientPublic.y);
}


#ifdef AVR_ARCH

extern unsigned int __heap_start;
extern void *__brkval;

int getFreeMemory()
{
    int free_memory;

    if ((int)__brkval == 0)
        free_memory = ((int)&free_memory) - ((int)&__heap_start);
    else
        free_memory = ((int)&free_memory) - ((int)__brkval);

    return free_memory;
}



#else


uint16_t getFreeMemory()
{
    return 0;
}

#endif


// static void lcdMemory()
// {
//     uint16_t freeNow = getFreeMemory();

//     lcdFillScreen(0x0000);

//     // Current free SRAM
//     lcdNumber(freeNow, 45, 35, 0xFFFF);

//     // Minimum free SRAM
//     lcdNumber(minFreeMemory, 45, 180, 0x07E0);
// }


// static void lcdGCMStatus(bool ok)
// {
//     lcdFillScreen(0x0000);

//     if (ok)
//     {
//         // GCM OK
//         lcdNumber(1, 80, 100, 0x07E0);
//     }
//     else
//     {
//         // GCM FAILED
//         lcdNumber(0, 80, 100, 0xF800);
//     }
// }
// ----------------------------------------------------------------
// Wait for and process Server ChangeCipherSpec and Finished
// ----------------------------------------------------------------
uint8_t tlsReadServerHandshake()
{
    // --- WAIT FOR SERVER CCS ---
    uint8_t contentType, versionMajor, versionMinor;
    uint16_t recordLength;
    if (!readTLSRecordHeader(contentType, versionMajor, versionMinor, recordLength)) {
        // showStage(81); // Header read failed
        return 81;
    }
    TLS_DEBUG_PRINTF(
        "SERVER NEXT RECORD: type=%02X version=%02X%02X len=%u\n",
        contentType,
        versionMajor,
        versionMinor,
        recordLength
    );
    /*Serial.print(F("SERVER CT="));
    Serial.println(contentType, HEX);
    Serial.print(F("SERVER RL="));
    Serial.println(recordLength);*/

    // Expect ChangeCipherSpec record (type 0x14, length 1)
    if (contentType != 0x14 || recordLength != 1)
    {
        // Wrong content type or length for CCS

        if (contentType == 0x15)
        {
            // TLS ALERT
            uint8_t alertLevel;
            uint8_t alertDescription;
            if (!readTLSByte(alertLevel) ||
                !readTLSByte(alertDescription))
            {
                return 82;
            }
            // Show alert description
            // showStage(alertDescription);
            // Show the record length
            // showStage(recordLength);

        }
        else if (contentType == 0x16)
        {
            // TLS HANDSHAKE
            // showStage(160);


            // Show record length
            // showStage(recordLength);

        }
        else if (contentType == 0x14)
        {
            // TLS CCS, but wrong record length
            // showStage(140);
            // Show record length
            // showStage(recordLength);
        }
        else
        {
            // Unknown content type
            // showStage(contentType);

            // Show record length
            // showStage(recordLength);

        }

        return 82;
    }
    uint8_t ccs;
    if (!readTLSByte(ccs)) {
        // showStage(83);
        return 83;
    }
    if (ccs != 0x01) {
        // showStage(84); // Payload must be 0x01 for CCS
        return 84;
    }
    // showStage(85); // Server CCS received and processed

    // --- READ SERVER FINISHED (Encrypted) ---
    if (!readTLSRecordHeader(contentType, versionMajor, versionMinor, recordLength)) {
        // showStage(86);
        return 86;
    }
    if (contentType != 0x16) {
        // showStage(87); // Expected handshake record
        return 87;
    }
    // TLS1.2 AES-GCM Finished record: 8B explicit nonce + 16B ciphertext + 16B tag = 40 bytes
    if (recordLength != 40) {
        // showStage(88); // Unexpected record length
        return 88;
    }
    // Read 8-byte explicit nonce
    uint8_t explicitNonce[8];
    for (uint8_t i = 0; i < 8; i++) {
        if (!readTLSByte(explicitNonce[i])) { /* showStage(89); */ return 89; }
    }



    // Read 16-byte ciphertext (Finished payload)
    uint8_t ciphertext[16];
    for (uint8_t i = 0; i < 16; i++) {
        if (!readTLSByte(ciphertext[i])) { /* showStage(91); */ return 91; }
    }
    // Read 16-byte auth tag
    uint8_t receivedTag[16];
    for (uint8_t i = 0; i < 16; i++)
    {
        if (!readTLSByte(receivedTag[i]))
        {
            //Serial.print(F("TAG READ FAILED AT BYTE: "));
            //Serial.println(i);
            return 92;
        }

        // Serial.print(F("TAG BYTE "));
        // Serial.print(i);
        // Serial.print(F(" = "));
        // Serial.println(receivedTag[i], HEX);
    }
    //Serial.println(F("ALL 16 TAG BYTES RECEIVED"));
    // --- VERIFY GCM TAG (Server Finished) ---
    // Build 12-byte nonce = serverWriteIV (4 bytes) || explicitNonce (8 bytes)
    uint8_t nonce[12];
    for (uint8_t i = 0; i < 4; i++) { nonce[i] = serverWriteIV[i]; }
    for (uint8_t i = 0; i < 8; i++) { nonce[4 + i] = explicitNonce[i]; }
    // Construct AAD = seq_num (8 bytes) || type (0x16) || version (0x03 0x03) || length (0x0010)
    // Here seq = 0 for Server Finished (first encrypted record)
    uint8_t aad[13] = {0};
    aad[8]  = 0x16;
    aad[9]  = 0x03;
    aad[10] = 0x03;
    aad[11] = 0x00;
    aad[12] = 0x10;
    uint8_t J0[16];

    for (uint8_t i = 0; i < 12; i++)
        J0[i] = nonce[i];

    J0[12] = 0x00;
    J0[13] = 0x00;
    J0[14] = 0x00;
    J0[15] = 0x01;

    uint8_t calcTag[16];
    gcmMakeTag(
        serverWriteKey,
        J0,
        aad,
        13,
        ciphertext,
        16,
        calcTag
    );
    
    for (uint8_t i = 0; i < 16; i++) {
        if (calcTag[i] != receivedTag[i]) {
            // showStage(93); // GCM authentication failed
            return 93;
        }
    }
    // showStage(94); // GCM tag verified

    // --- DECRYPT SERVER FINISHED ---
    // CTR decrypt: set counter = nonce || 0x00000001 (i.e. initial counter J0 incremented)
    uint8_t counter[16];
    for (uint8_t i = 0; i < 12; i++) { counter[i] = nonce[i]; }
    counter[12] = 0x00;
    counter[13] = 0x00;
    counter[14] = 0x00;
    counter[15] = 0x01;
    gcmIncrementCounter(counter);  // now counter = J0 + 1
    gcmCtrCrypt(serverWriteKey, counter, ciphertext, 16); // decrypt in place

    // --- VERIFY FINISHED HANDSHAKE CONTENTS ---
    // First 4 bytes should be Handshake Header: (0x14, 0x00 0x00 0x0C) for Finished of length 12
    if (ciphertext[0] != 0x14 || ciphertext[1] != 0x00 ||
        ciphertext[2] != 0x00 || ciphertext[3] != 0x0C)
    {
        // showStage(95); // Malformed Finished header
        return 95;
    }
    // Compute expected verify_data = PRF(master_secret, "server finished", Hash(transcript))
    uint8_t serverHash[32];
    uint8_t serverFinished[12];

    tlsTranscriptFinal(serverHash);

    const uint8_t label[] PROGMEM = "server finished";

    tlsPrfSha256(
        tlsMasterSecret,
        48,
        label,
        15,
        serverHash,
        32,
        serverFinished,
        nullptr,
        12
    );



    for (uint8_t i = 0; i < 12; i++) {
        if (ciphertext[4 + i] != serverFinished[i]) {
            return 96;
        }
    }

    // --- ACCEPT SERVER FINISHED ---
    // Update transcript with plaintext Finished (handshake header + verify_data)
    for (uint8_t i = 0; i < 16; i++) {
        tlsTranscriptUpdateByte(ciphertext[i]);
    }
    tlsReadSequence++;  // increment server record sequence
    //showStage(97);      // Server Finished verified
    return 97;          // Handshake complete
}

uint8_t runTLS()
{
    if (!networkConnect())
    {
        return 12;
    }

    // showStage(10);
    // =======================================================
    // CLIENT HELLO
    // =======================================================
    Serial.print(F("FREE RAM="));
    Serial.println(getFreeMemory());
    tlsTranscriptInit();
    // Serial.println(F("SENDING CLIENT HELLO"));
    size_t sent = sendClientHello();
    // Serial.print(F("CLIENT HELLO SENT: "));
    // Serial.println(sent);
    if (sent != clientHelloLength)
    {
        // Serial.println(F("FAIL 15: CLIENT HELLO SEND"));
        return 15;
    }
    // showStage(20);

    // =======================================================
    // RECEIVE TLS RECORDS
    // =======================================================
    // Serial.println(F("WAITING FOR SERVER"));
    unsigned long start = millis();

    while (millis() - start < 15000UL)
    {
        if (!client.available())
        {
            delay(10);
            continue;
        }

        while (client.connected())
        {
            //Serial.println(F("rt: Connected"));
            tlsTranscriptRecord = false;

            uint8_t contentType;
            uint8_t versionMajor;
            uint8_t versionMinor;
            uint16_t recordLength;

            // ---------------------------------------------------
            // TLS RECORD HEADER
            // ---------------------------------------------------
            if (!readTLSRecordHeader(
                    contentType,
                    versionMajor,
                    versionMinor,
                    recordLength))
            {
                // Serial.println(F("FAIL 20: RECORD HEADER"));
                return 20;
            }

             Serial.print(F("RX RECORD type="));
             Serial.print(contentType, HEX);
            // Serial.print(F(" ver="));
            // Serial.print(versionMajor, HEX);
            // Serial.print(versionMinor, HEX);
            // Serial.print(F(" len="));
            // Serial.println(recordLength);
            // Serial.print(F("TYPE="));
            // Serial.print(contentType, HEX);
            // Serial.print(F(" LEN="));
            // Serial.println(recordLength);

            tlsTranscriptRecord = (contentType == 0x16);
            // ===================================================
            // HANDSHAKE
            // ===================================================

            if (contentType == 0x16)
            {
                
                tlsTranscriptRecord = true;
                 uint8_t firstByte;
                if (!readTLSByte(firstByte))
                {
                    return 21;
                }

                    //showStage(firstByte);
                    //showStage(recordLength);
                // =================================================
                // SERVER HELLO
                // =================================================
                //Serial.println(firstByte, HEX);
                if (firstByte == 0x02)
                {
                    uint32_t handshakeLength;

                    if (!readTLSU24(handshakeLength))
                    {
                        // Serial.println(F("FAIL 22: HANDSHAKE LENGTH"));
                        return 22;
                    }

                    if (!readTLSByte(versionMajor) ||
                        !readTLSByte(versionMinor))
                    {
                        // Serial.println(F("FAIL 22: VERSION"));
                        return 23;
                    }

                    // Server random
                    for (uint8_t i = 0; i < 32; i++)
                    {
                        if (!readTLSByte(serverRandom[i]))
                        {    Serial.print(F("FAIL 24 i="));
                            Serial.println(i);
                            // Serial.println(F("FAIL 22: SERVER RANDOM"));
                            return 24;
                        }
                    }

                    // Session ID
                    uint8_t sessionIdLength;

                    if (!readTLSByte(sessionIdLength))
                    {
                        // Serial.println(F("FAIL 22: SESSION ID LENGTH"));
                        return 25;
                    }

                    if (!consumeTLSBytes(sessionIdLength))
                    {
                        // Serial.println(F("FAIL 22: SESSION ID"));
                        return 26;
                    }

                    // Cipher suite
                    uint16_t cipherSuite;
                    if (!readTLSU16(cipherSuite))
                    {
                        // Serial.println(F("FAIL 22: CIPHER SUITE"));
                        return 27;
                    }

                    // Compression
                    uint8_t compressionMethod;

                    if (!readTLSByte(compressionMethod))
                    {
                        // Serial.println(F("FAIL 22: COMPRESSION METHOD"));
                        return 28;
                    }

                    if (compressionMethod != 0x00)
                    {
                        // Serial.println(F("FAIL 23: COMPRESSION METHOD NOT NULL"));
                        return 29;
                    }

                    // Extensions
                    uint16_t extensionsLength;

                    if (!readTLSU16(extensionsLength))
                    {
                        // Serial.println(F("FAIL 22: EXTENSIONS LENGTH"));
                        return 291;
                    }

                    if (!consumeTLSBytes(extensionsLength))
                    {
                        // Serial.println(F("FAIL 22: EXTENSIONS"));
                        return 292;
                    }

                    // ServerHello succeeded.
                    // showStage(30);
                    uint8_t debugTranscript[32];
                    tlsTranscriptFinal(debugTranscript);

                }

                // =================================================
                // SERVER KEY EXCHANGE
                // =================================================

                else if (firstByte == 0x0C)
                {
                    uint32_t handshakeLength;

                    if (!readTLSU24(handshakeLength))
                    {
                        // Serial.println(F("FAIL 30: SERVER KEY EXCHANGE LENGTH"));
                        return 30;
                    }

                    if (handshakeLength !=
                        (uint32_t)(recordLength - 4))
                    {
                        // Serial.println(F("FAIL 30: SERVER KEY EXCHANGE SIZE"));
                        return 30;
                    }

                    // ------------------------------------------------
                    // EC PARAMETERS
                    // ------------------------------------------------

                    uint8_t curveType;

                    if (!readTLSByte(curveType))
                    {
                        // Serial.println(F("FAIL 31: CURVE TYPE"));
                        return 31;
                    }

                    uint16_t namedCurve;

                    if (!readTLSU16(namedCurve))
                    {
                        // Serial.println(F("FAIL 31: NAMED CURVE"));
                        return 31;
                    }

                    if (curveType != 0x03 ||
                        namedCurve != 0x0017)
                    {
                        // Serial.println(F("FAIL 31: UNSUPPORTED CURVE"));
                        return 31;
                    }

                    // ------------------------------------------------
                    // SERVER EC POINT
                    // ------------------------------------------------

                    uint8_t pointLength;

                    if (!readTLSByte(pointLength))
                    {
                        // Serial.println(F("FAIL 32: EC POINT LENGTH"));
                        return 32;
                    }

                    if (pointLength != 65)
                    {
                        // Serial.println(F("FAIL 32: INVALID EC POINT LENGTH"));
                        return 32;
                    }

                    uint8_t pointFormat;

                    if (!readTLSByte(pointFormat))
                    {
                        // Serial.println(F("FAIL 32: EC POINT FORMAT"));
                        return 32;
                    }

                    if (pointFormat != 0x04)
                    {
                        // Serial.println(F("FAIL 32: UNSUPPORTED EC POINT FORMAT"));
                        return 32;
                    }

                    // X
                    for (uint8_t i = 0; i < 32; i++)
                    {
                        uint8_t value;

                        if (!readTLSByte(value))
                        {
                            // Serial.println(F("FAIL 32: SERVER EC POINT X"));
                            return 32;
                        }

                        ecc.point1.x.v[31 - i] = value;
                    }

                    // Y
                    for (uint8_t i = 0; i < 32; i++)
                    {
                        uint8_t value;

                        if (!readTLSByte(value))
                        {
                            // Serial.println(F("FAIL 32: SERVER EC POINT Y"));
                            return 32;
                        }

                        ecc.point1.y.v[31 - i] = value;
                    }
                    // ------------------------------------------------
                    // CLIENT PRIVATE SCALAR
                    // ------------------------------------------------

                    zero256(ecdhePrivate);

                    // Current test scalar.
                    ecdhePrivate.v[0] = 2;

                    // ------------------------------------------------
                    // CLIENT PUBLIC = d * G
                    // ------------------------------------------------

                    pointScalarMultiplyGeneratorProjective(
                        ecdhePoint,
                        ecdhePrivate
                    );

                    pointProjectiveToAffine(
                        ecdheClientPublic,
                        ecdhePoint
                    );

                    // ------------------------------------------------
                    // SHARED SECRET = d * SERVER PUBLIC
                    // ------------------------------------------------
                    //Serial.println("S");
                    pointScalarMultiplyProjective(
                        ecdhePoint,
                        ecdhePrivate,
                        ecc.point1
                    );
                    //Serial.println("M");
                    pointProjectiveToAffineX(
                        ecc.temp1,
                        ecdhePoint
                    );

                    //Serial.println("A");
                    // ------------------------------------------------
                    // TLS KEYS
                    // ------------------------------------------------


                    // ------------------------------------------------
                    // Signature
                    // ------------------------------------------------

                    uint8_t hashAlgorithm;
                    uint8_t signatureAlgorithm;
                    uint16_t signatureLength;

                    /*Serial.print(F("CT="));
                    Serial.println(contentType);
                    Serial.print(F("RL="));
                    Serial.println(recordLength);*/

                    if (!readTLSByte(hashAlgorithm))
                    {
                        return 36;
                    }

                    if (!readTLSByte(signatureAlgorithm))
                    {
                        return 36;
                    }

                    //Serial.println(F("SB"));
                    if (!readTLSU16(signatureLength))
                    {
                        //Serial.println(F("SLF"));
                        return 36;
                    }

                    //Serial.print(F("SL="));
                    //Serial.println(signatureLength);

                    if (!consumeTLSBytes(signatureLength))
                    {
                        //Serial.println(F("SDF"));
                        return 36;
                    }
                    //Serial.println(F("SO"));
                    // showStage(40);
                    uint8_t debugTranscript[32];
                    tlsTranscriptFinal(debugTranscript);

                }

                // =================================================
                // SERVER HELLO DONE
                // =================================================
                //Serial.print(F("FB="));

                else if (firstByte == 0x0E)
                {
                    //Serial.println(F("SHD"));
                    uint8_t b1;
                    uint8_t b2;
                    uint8_t b3;

                    if (!readTLSByte(b1) ||
                        !readTLSByte(b2) ||
                        !readTLSByte(b3))
                    {
                        return 41;
                    }

                    if (b1 != 0 ||
                        b2 != 0 ||
                        b3 != 0)
                    {
                        return 41;
                    }
                    uint8_t debugTranscript[32];
                    tlsTranscriptFinal(debugTranscript);

                    // ------------------------------------------------
                    // CLIENT KEY EXCHANGE
                    // ------------------------------------------------
                    tlsTranscriptRecord = false;
                    size_t ckxSent = sendClientKeyExchange(ecdheClientPublic);

                    // Serial.print(F("CKX SENT: "));
                    // Serial.println(ckxSent);

                    // Serial.print(F("CONNECTED AFTER CKX: "));
                    // Serial.println(client.connected());

                    // Serial.print(F("AVAILABLE AFTER CKX: "));
                    // Serial.println(client.available());

                    if (ckxSent != 75)
                    {
                        // Serial.println(F("FAIL 42: CLIENT KEY EXCHANGE SEND"));
                        return 42;
                    }

                    // showStage(60);

                    // ------------------------------------------------
                    // ADD CLIENT KEY EXCHANGE TO TRANSCRIPT
                    // ------------------------------------------------

                    tlsTranscriptUpdateByte(0x10);
                    tlsTranscriptUpdateByte(0x00);
                    tlsTranscriptUpdateByte(0x00);
                    tlsTranscriptUpdateByte(0x42);
                    tlsTranscriptUpdateByte(0x41);
                    tlsTranscriptUpdateByte(0x04);

                    for (int8_t i = 31; i >= 0; i--)
                    {
                        tlsTranscriptUpdateByte(
                            ecdheClientPublic.x.v[i]
                        );
                    }

                    for (int8_t i = 31; i >= 0; i--)
                    {
                        tlsTranscriptUpdateByte(
                            ecdheClientPublic.y.v[i]
                        );
                    }

                    // ------------------------------------------------
                    // TRANSCRIPT HASH
                    // ------------------------------------------------
                    
                    
                    uint8_t clientFinishedTranscript[32];
                    SHA256Context savedTranscriptContext;

                    savedTranscriptContext = tlsHmacContext;

                    tlsTranscriptFinal(clientFinishedTranscript);
                    deriveTLSKeys();

                    tlsHmacContext = savedTranscriptContext;
                    // ------------------------------------------------
                    // CLIENT FINISHED VERIFY DATA
                    // ------------------------------------------------

                    const uint8_t clientFinishedLabel[]
                        PROGMEM = "client finished";

                    uint8_t clientFinished[16];

                    SHA256Context savedClientFinishedTranscript;

                    savedClientFinishedTranscript = tlsHmacContext;

                    tlsPrfSha256(
                        tlsMasterSecret,
                        48,
                        clientFinishedLabel,
                        15,
                        clientFinishedTranscript,
                        32,
                        clientFinished + 4,
                        nullptr,
                        12
                    );

                    tlsHmacContext = savedClientFinishedTranscript;

                    clientFinished[0] = 0x14;
                    clientFinished[1] = 0x00;
                    clientFinished[2] = 0x00;
                    clientFinished[3] = 0x0C;

                    for (uint8_t i = 0; i < 16; i++)
                    {
                        tlsTranscriptUpdateByte(clientFinished[i]);
                    }


                    // Serial.print(F("CONNECTED AFTER FINISHED COMPUTE: "));
                    // Serial.println(client.connected());
                    // ------------------------------------------------
                    // CHANGE CIPHER SPEC
                    // ------------------------------------------------

                    uint8_t afterClientFinished[32];
                    tlsTranscriptFinal(afterClientFinished);
                    if (!tlsSendChangeCipherSpec())
                    {
                        // Serial.println(F("FAIL 52: CHANGE CIPHER SPEC SEND"));
                        return 52;
                    }

                    // showStage(70);

                    // ------------------------------------------------
                    // FIRST ENCRYPTED RECORD
                    // ------------------------------------------------

                    tlsWriteSequence = 0;
                    /*Serial.print("CK=");
                    for (uint8_t i = 0; i < 16; i++)
                    {
                        if (clientWriteKey[i] < 16) Serial.print('0');
                        Serial.print(clientWriteKey[i], HEX);
                    }
                    Serial.println();

                    Serial.print("CIV=");
                    for (uint8_t i = 0; i < 4; i++)
                    {
                        if (clientWriteIV[i] < 16) Serial.print('0');
                        Serial.print(clientWriteIV[i], HEX);
                    }
                    Serial.println();

                    Serial.print("FIN=");
                    for (uint8_t i = 0; i < 16; i++)
                    {
                        if (tlsHmacInnerHash[i] < 16) Serial.print('0');
                        Serial.print(tlsHmacInnerHash[i], HEX);
                    }
                    Serial.println();*/

                        if (!tlsSendGCMRecord(
                                0x16,
                                clientFinished,
                                16))
                        {
                            return 53;
                    }
                    // showStage(80);
                    //Serial.println(F("B"));
                    // NOW WAIT FOR SERVER CCS + SERVER FINISHED
                    uint8_t serverStage = tlsReadServerHandshake();
                    //Serial.print("ZZ=");
                    //Serial.println(serverStage);

                    if (serverStage != 90)
                    {
                        return serverStage;
                    }

                    // showStage(90);
                    return 90;

                }

                // =================================================
                // UNKNOWN HANDSHAKE
                // =================================================

                else
                {
                    if (recordLength == 0)
                    {
                        // Serial.println(F("FAIL 21: UNKNOWN EMPTY HANDSHAKE"));
                        return 21;
                    }

                    for (uint16_t i = 1;
                         i < recordLength;
                         i++)
                    {
                        uint8_t value;

                        if (!readTLSByte(value))
                        {
                            // Serial.println(F("FAIL 21: UNKNOWN HANDSHAKE DATA"));
                            return 21;
                        }
                    }
                }
            }

            // =======================================================
            // ALERT
            // =======================================================

            else if (contentType == 0x15)
            {
                uint8_t alertLevel;
                uint8_t alertDescription;

                if (recordLength >= 2 &&
                    readTLSByte(alertLevel) &&
                    readTLSByte(alertDescription))
                {
                    if (recordLength > 2)
                        consumeTLSBytes(recordLength - 2);
                }
                else
                {
                    consumeTLSBytes(recordLength);
                }

                return 90;
            }

            // =======================================================
            // OTHER RECORD
            // =======================================================

            else
            {
                if (!consumeTLSBytes(recordLength))
                {
                    // Serial.println(F("FAIL 91: UNKNOWN TLS RECORD"));
                    return 91;
                }
            }
        }

        if (!client.connected())
        {
            // Serial.println(F("FAIL 92: SERVER DISCONNECTED"));
            return 92;
        }
    }

    // Serial.println(F("FAIL 93: SERVER RESPONSE TIMEOUT"));
    return 93;
}


uint8_t diagnoseTCP()
{
    // -------------------------------------------------
    // TEST 1: Gateway TCP
    // -------------------------------------------------

    IPAddress gateway = Ethernet.gatewayIP();

    if (!client.connect(gateway, 80))
        return 20;

    client.stop();


    // -------------------------------------------------
    // TEST 2: Internet TCP by IP, port 80
    // -------------------------------------------------

    if (!client.connect(IPAddress(1, 1, 1, 1), 80))
        return 30;

    client.stop();


    // -------------------------------------------------
    // TEST 3: Internet TCP by IP, port 443
    // -------------------------------------------------

    if (!client.connect(IPAddress(142, 250, 72, 14), 443))
        return 40;

    client.stop();


    // -------------------------------------------------
    // TEST 4: Hostname -> DNS + TCP :443
    // -------------------------------------------------

    if (!client.connect(F("google.com"), 443))
        return 50;

    client.stop();


    // -------------------------------------------------
    // TEST 5: Binance hostname -> DNS + TCP :443
    // -------------------------------------------------

    if (!client.connect(IPAddress(142, 250, 72, 14), 443))
        return 60;

    client.stop();


    // -------------------------------------------------
    // ALL NETWORK TESTS PASSED
    // -------------------------------------------------

    return 70;
}

/*
void showStage(uint8_t stage)
{
    lcdFillScreen(0x0000);

    lcdNumber(
        stage,
        60,
        100,
        0x07E0
    );
}
*/

void printIP(const IPAddress &ip)
{
    Serial.print(F("IP="));
    Serial.print(ip[0]);
    Serial.print(F("."));
    Serial.print(ip[1]);
    Serial.print(F("."));
    Serial.print(ip[2]);
    Serial.print(F("."));
    Serial.println(ip[3]);
}
bool testTCP(const char *hostname, uint16_t port)
{
    unsigned long start = millis();

    if (client.connect(hostname, port))
    {
        client.stop();

        return true;
    }

    return false;
}
bool testTCPByIP(
    const IPAddress &ip,
    uint16_t port
)
{
    printIP(ip);
    unsigned long start = millis();

    if (client.connect(ip, port))
    {
        client.stop();

        return true;
    }

    return false;
}

static bool tlsSendHttpGet()
{
    const char request[] =
        "GET /api/v3/time HTTP/1.1\r\n"
        "Host: api.coinpaprika.com\r\n"
        "Connection: close\r\n"
        "\r\n";

    return tlsSendGCMRecord(
        0x17,                         // Application Data
        (uint8_t *)request,
        sizeof(request) - 1
    );
}


#ifdef USE_DNS_LIB


bool networkConnect()
{
    DNSClient dnsClient;

    IPAddress ip;
    IPAddress dnsIP = Ethernet.dnsServerIP();

    dnsClient.begin(dnsIP);
    const char *hostname = "api.coinpaprika.com";
    const uint16_t port = 443;
    if (dnsClient.getHostByName(hostname, ip) != 1)
        return false;
    Serial.println("C");
    return client.connect(ip, port);
}
#else


bool networkConnect()
{
//     DNSClient dnsClient;

//     IPAddress ip;
//     IPAddress dnsIP = Ethernet.dnsServerIP();

    //dnsClient.begin(dnsIP);
    const char *hostname = "api.coinpaprika.com";
    const uint16_t port = 443;
    //if (dnsClient.getHostByName(hostname, ip) != 1)
    //    return false;

    return client.connect(hostname, port);
}

#endif

#if defined(AVR_ARCH)

void initSerial()
{
    Serial.begin(115200);
    delay(1000);
    Serial.println(F("Serial initialized"));
}

void setup()
{
    #ifdef TURN_LCD_ON
    lcdInit();
    #endif

    initSerial();

    if (Ethernet.begin(mac) == 0)
    {
        #ifdef TURN_LCD_ON
        lcdFillScreen(0x0000);
        lcdNumber(1, 60, 100, 0xF800);
        #endif
        while (1)
            ;
    }

    printIP(Ethernet.localIP());

    delay(1000);
    
    uint8_t stage = runTLS();

    #ifdef TURN_LCD_ON
    lcdFillScreen(0x0000);
    lcdNumber(
        stage,
        60,
        100,
        stage >= 60 ? 0x07E0 : 0xF800
    );
    #endif

    while (1);
}

void loop()
{
}

#elif defined(X64_ARCH)

int main()
{
    std::printf("X64 TEST START\n");

    // --------------------------------------------------
    // AES-128
    // --------------------------------------------------
    uint8_t aesKey[16] =
    {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };

    uint8_t aesBlock[16] =
    {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };

    aes128EncryptBlock(aesKey, aesBlock);

    std::printf("AES=");
    for (uint8_t i = 0; i < 16; i++)
        std::printf("%02X", aesBlock[i]);
    std::printf("\n");

    // --------------------------------------------------
    // HMAC-SHA256
    // --------------------------------------------------
    const uint8_t hkey[] = "key";
    const uint8_t hdata[] = "The quick brown fox jumps over the lazy dog";
    uint8_t hout[32];

    hmacSha256(
        hkey,
        3,
        hdata,
        sizeof(hdata) - 1,
        hout
    );

    std::printf("HMAC=");
    for (uint8_t i = 0; i < 32; i++)
        std::printf("%02X", hout[i]);
    std::printf("\n");

const uint8_t testKey[] = {
    0xC6,0xD7,0xEE,0x9D,0xA5,0x21,0x13,0x82,
    0x00,0x8B,0x55,0x58,0xE9,0x1A,0xC5,0x18,
    0x05,0x3F,0x91,0x24,0x11,0x78,0x42,0x02,
    0x23,0x99,0x1F,0xF0,0x01,0x49,0xA6,0x88,
    0x29
};

const uint8_t testData[] = {
    0x6D,0x61,0x73,0x74,0x65,0x72,0x20,0x73,0x65,0x63,0x72,0x65,0x74,

    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,

    0x6A,0xA1,0xE4,0x76,0x3A,0xC1,0x13,0x7C,
    0x07,0x5C,0xEC,0x65,0x84,0x3F,0xF2,0xDF,
    0xE1,0x20,0x78,0x0D,0x33,0x0A,0xA3,0x96,
    0x44,0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,
    0x01
};

uint8_t testHmac[32];

hmacSha256(testKey, 32, testData, 77, testHmac);

std::printf("DIRECT_HMAC=");
for (uint8_t i = 0; i < 32; i++)
    std::printf("%02X", testHmac[i]);
std::printf("\n");
       // --------------------------------------------------
    // TLS HANDSHAKE
    // --------------------------------------------------
    std::printf("TLS HANDSHAKE ...\n");

    uint8_t result = runTLS();

    std::printf("TLS RESULT=%u\n", result);

    client.stop();

    std::printf("X64 TEST END\n");

    return result == 0 ? 0 : 1;
}

#endif
