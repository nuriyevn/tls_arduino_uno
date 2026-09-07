#ifndef LCD_H
#define LCD_H

#include <Arduino.h>
#include "U256.h"

#define LCD_RST A4
#define LCD_CS  A3
#define LCD_RS  A2
#define LCD_WR  A1
#define LCD_RD  A0

#define LCD_D0 8
#define LCD_D1 9
#define LCD_D2 2
#define LCD_D3 3
#define LCD_D4 4
#define LCD_D5 5
#define LCD_D6 6
#define LCD_D7 7


static void lcdSetWriteDir()
{
    pinMode(LCD_D0, OUTPUT);
    pinMode(LCD_D1, OUTPUT);
    pinMode(LCD_D2, OUTPUT);
    pinMode(LCD_D3, OUTPUT);
    pinMode(LCD_D4, OUTPUT);
    pinMode(LCD_D5, OUTPUT);
    pinMode(LCD_D6, OUTPUT);
    pinMode(LCD_D7, OUTPUT);
}


static inline void lcdWrite8(uint8_t data)
{
    PORTB = (PORTB & 0xFC) | (data & 0x03);
    PORTD = (PORTD & 0x03) | (data & 0xFC);
}


static inline void lcdWrite16(uint16_t data)
{
    lcdWrite8(data >> 8);

    PORTC &= ~(1 << PC1);
    PORTC |=  (1 << PC1);

    lcdWrite8(data);

    PORTC &= ~(1 << PC1);
    PORTC |=  (1 << PC1);
}

static void lcdWriteCommand(uint16_t command)
{
    lcdSetWriteDir();

    digitalWrite(LCD_CS, LOW);
    digitalWrite(LCD_RS, LOW);
    digitalWrite(LCD_RD, HIGH);
    digitalWrite(LCD_WR, HIGH);

    lcdWrite16(command);

    digitalWrite(LCD_CS, HIGH);
}


static void lcdWriteData(uint16_t data)
{
    lcdSetWriteDir();

    digitalWrite(LCD_CS, LOW);
    digitalWrite(LCD_RS, HIGH);
    digitalWrite(LCD_RD, HIGH);
    digitalWrite(LCD_WR, HIGH);

    lcdWrite16(data);

    digitalWrite(LCD_CS, HIGH);
}


static void lcdWriteRegister(uint16_t addr, uint16_t data)
{
    lcdWriteCommand(addr);
    lcdWriteData(data);
}


static void lcdReset()
{
    digitalWrite(LCD_RST, LOW);
    delay(2);
    digitalWrite(LCD_RST, HIGH);
    delay(10);
}


static void lcdInit()
{
    pinMode(LCD_CS, OUTPUT);
    digitalWrite(LCD_CS, HIGH);

    pinMode(LCD_RS, OUTPUT);
    digitalWrite(LCD_RS, HIGH);

    pinMode(LCD_WR, OUTPUT);
    digitalWrite(LCD_WR, HIGH);

    pinMode(LCD_RD, OUTPUT);
    digitalWrite(LCD_RD, HIGH);

    pinMode(LCD_RST, OUTPUT);
    digitalWrite(LCD_RST, HIGH);

    lcdSetWriteDir();

    lcdReset();

    // LGDP4535 initialization

    lcdWriteRegister(0x0015, 0x0030);
    lcdWriteRegister(0x009A, 0x0010);
    lcdWriteRegister(0x0011, 0x0020);
    lcdWriteRegister(0x0010, 0x3428);
    lcdWriteRegister(0x0012, 0x0002);
    lcdWriteRegister(0x0013, 0x1038);

    delay(40);

    lcdWriteRegister(0x0012, 0x0012);

    delay(40);

    lcdWriteRegister(0x0010, 0x3420);
    lcdWriteRegister(0x0013, 0x3045);

    delay(70);

    lcdWriteRegister(0x0030, 0x0000);
    lcdWriteRegister(0x0031, 0x0402);
    lcdWriteRegister(0x0032, 0x0307);
    lcdWriteRegister(0x0033, 0x0304);
    lcdWriteRegister(0x0034, 0x0004);
    lcdWriteRegister(0x0035, 0x0401);
    lcdWriteRegister(0x0036, 0x0707);
    lcdWriteRegister(0x0037, 0x0305);
    lcdWriteRegister(0x0038, 0x0610);
    lcdWriteRegister(0x0039, 0x0610);

    lcdWriteRegister(0x0001, 0x0100);
    lcdWriteRegister(0x0002, 0x0300);
    lcdWriteRegister(0x0003, 0x1030);
    lcdWriteRegister(0x0008, 0x0808);
    lcdWriteRegister(0x000A, 0x0008);

    lcdWriteRegister(0x0060, 0x2700);
    lcdWriteRegister(0x0061, 0x0001);

    lcdWriteRegister(0x0090, 0x013E);
    lcdWriteRegister(0x0092, 0x0100);
    lcdWriteRegister(0x0093, 0x0100);
    lcdWriteRegister(0x00A0, 0x3000);
    lcdWriteRegister(0x00A3, 0x0010);

    lcdWriteRegister(0x0007, 0x0001);
    lcdWriteRegister(0x0007, 0x0021);
    lcdWriteRegister(0x0007, 0x0023);
    lcdWriteRegister(0x0007, 0x0033);
    lcdWriteRegister(0x0007, 0x0133);

    delay(50);
}


static void lcdSetWindow(
    uint16_t x0,
    uint16_t y0,
    uint16_t x1,
    uint16_t y1)
{
    lcdWriteRegister(0x0020, x0);
    lcdWriteRegister(0x0021, y0);
    lcdWriteRegister(0x0050, x0);
    lcdWriteRegister(0x0051, x1);
    lcdWriteRegister(0x0052, y0);
    lcdWriteRegister(0x0053, y1);

    lcdWriteCommand(0x0022);
}


static void lcdFillScreen(uint16_t color)
{
    lcdSetWindow(0, 0, 239, 319);

    lcdSetWriteDir();

    digitalWrite(LCD_CS, LOW);
    digitalWrite(LCD_RS, HIGH);
    digitalWrite(LCD_RD, HIGH);
    digitalWrite(LCD_WR, HIGH);

    for (uint32_t i = 0; i < 76800UL; i++)
    {
        lcdWrite16(color);
    }

    digitalWrite(LCD_CS, HIGH);
}


static void lcdFillRect(
    uint16_t x0,
    uint16_t y0,
    uint16_t x1,
    uint16_t y1,
    uint16_t color)
{
    lcdSetWindow(x0, y0, x1, y1);

    digitalWrite(LCD_CS, LOW);
    digitalWrite(LCD_RS, HIGH);
    digitalWrite(LCD_RD, HIGH);
    digitalWrite(LCD_WR, HIGH);

    uint32_t pixels =
        (uint32_t)(x1 - x0 + 1) *
        (uint32_t)(y1 - y0 + 1);

    for (uint32_t i = 0; i < pixels; i++)
        lcdWrite16(color);

    digitalWrite(LCD_CS, HIGH);
}
static void lcdDigit(
    uint8_t digit,
    uint16_t x,
    uint16_t y,
    uint16_t color)
{
    static const uint8_t segments[10] =
    {
        0b1111110, // 0
        0b0110000, // 1
        0b1101101, // 2
        0b1111001, // 3
        0b0110011, // 4
        0b1011011, // 5
        0b1011111, // 6
        0b1110000, // 7
        0b1111111, // 8
        0b1111011  // 9
    };

    uint8_t s = segments[digit];

    const uint16_t w = 30;
    const uint16_t h = 8;
    const uint16_t gap = 4;

    // A
    if (s & 0b1000000)
        lcdFillRect(x + gap, y, x + w - gap, y + h, color);

    // B
    if (s & 0b0100000)
        lcdFillRect(
            x + w - h,
            y + gap,
            x + w,
            y + 50,
            color);

    // C
    if (s & 0b0010000)
        lcdFillRect(
            x + w - h,
            y + 50,
            x + w,
            y + 96,
            color);

    // D
    if (s & 0b0001000)
        lcdFillRect(
            x + gap,
            y + 96,
            x + w - gap,
            y + 96 + h,
            color);

    // E
    if (s & 0b0000100)
        lcdFillRect(
            x,
            y + 50,
            x + h,
            y + 96,
            color);

    // F
    if (s & 0b0000010)
        lcdFillRect(
            x,
            y + gap,
            x + h,
            y + 50,
            color);

    // G
    if (s & 0b0000001)
        lcdFillRect(
            x + gap,
            y + 46,
            x + w - gap,
            y + 54,
            color);
}

static void lcdNumber(
    uint16_t value,
    uint16_t x,
    uint16_t y,
    uint16_t color)
{
    uint8_t d0 = value / 1000;
    uint8_t d1 = (value / 100) % 10;
    uint8_t d2 = (value / 10) % 10;
    uint8_t d3 = value % 10;

    lcdDigit(d0, x,       y, color);
    lcdDigit(d1, x + 38,  y, color);
    lcdDigit(d2, x + 76,  y, color);
    lcdDigit(d3, x + 114, y, color);
}

/*
static void lcdHexDigit(
    uint8_t digit,
    uint16_t x,
    uint16_t y,
    uint16_t color)
{
    static const uint8_t segments[16] =
    {
        0b1111110, // 0
        0b0110000, // 1
        0b1101101, // 2
        0b1111001, // 3
        0b0110011, // 4
        0b1011011, // 5
        0b1011111, // 6
        0b1110000, // 7
        0b1111111, // 8
        0b1111011, // 9

        0b1110111, // A
        0b0011111, // b
        0b1001110, // C
        0b0111101, // d
        0b1001111, // E
        0b1000111  // F
    };

    uint8_t s = segments[digit & 0x0F];

    const uint16_t w = 30;
    const uint16_t h = 8;
    const uint16_t gap = 4;

    // A
    if (s & 0b1000000)
        lcdFillRect(x + gap, y, x + w - gap, y + h, color);

    // B
    if (s & 0b0100000)
        lcdFillRect(
            x + w - h,
            y + gap,
            x + w,
            y + 50,
            color);

    // C
    if (s & 0b0010000)
        lcdFillRect(
            x + w - h,
            y + 50,
            x + w,
            y + 96,
            color);

    // D
    if (s & 0b0001000)
        lcdFillRect(
            x + gap,
            y + 96,
            x + w - gap,
            y + 96 + h,
            color);

    // E
    if (s & 0b0000100)
        lcdFillRect(
            x,
            y + 50,
            x + h,
            y + 96,
            color);

    // F
    if (s & 0b0000010)
        lcdFillRect(
            x,
            y + gap,
            x + h,
            y + 50,
            color);

    // G
    if (s & 0b0000001)
        lcdFillRect(
            x + gap,
            y + 46,
            x + w - gap,
            y + 54,
            color);
}

static void lcdHexDigitBig(
    uint8_t digit,
    uint16_t x,
    uint16_t y,
    uint16_t color)
{
    static const uint8_t font[16][5] =
    {
        {0x1F,0x11,0x11,0x11,0x1F}, // 0
        {0x04,0x0C,0x04,0x04,0x1F}, // 1
        {0x1F,0x01,0x1F,0x10,0x1F}, // 2
        {0x1F,0x01,0x0F,0x01,0x1F}, // 3
        {0x11,0x11,0x1F,0x01,0x01}, // 4
        {0x1F,0x10,0x1F,0x01,0x1F}, // 5
        {0x1F,0x10,0x1F,0x11,0x1F}, // 6
        {0x1F,0x01,0x02,0x04,0x04}, // 7
        {0x1F,0x11,0x1F,0x11,0x1F}, // 8
        {0x1F,0x11,0x1F,0x01,0x1F}, // 9
        {0x1F,0x11,0x1F,0x11,0x11}, // A
        {0x1E,0x11,0x1E,0x11,0x1E}, // B
        {0x1F,0x10,0x10,0x10,0x1F}, // C
        {0x1E,0x11,0x11,0x11,0x1E}, // D
        {0x1F,0x10,0x1F,0x10,0x1F}, // E
        {0x1F,0x10,0x1F,0x10,0x10}  // F
    };

    digit &= 0x0F;

    for (uint8_t row = 0; row < 5; row++)
    {
        for (uint8_t col = 0; col < 5; col++)
        {
            if (font[digit][row] & (1 << (4 - col)))
            {
                lcdFillRect(
                    x + col * 4,
                    y + row * 6,
                    x + col * 4 + 3,
                    y + row * 6 + 5,
                    color
                );
            }
        }
    }
}
*/

#endif