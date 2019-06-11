#include <msp430.h>
#include <stdint.h>
#include "driverlib/driverlib.h"

// DEMO AND PERF EVAL OF CBC AES-128 ENCRYPTION

    // iv   00010203 04050607 08090A0B 0C0D0E0F
    // key  2B7E1516 28AED2A6 ABF71588 09CF4F3C

    // pt     6BC1BEE2 2E409F96 E93D7E11 7393172A
    // pt     AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
    // pt     30C81C46 A35CE411 E5FBC119 1A0A52EF
    // pt     F69F2445 DF4F9B17 AD2B417B E66C3710

    // ct     7649ABAC 8119B246 CEE98E9B 12E9197D
    // ct     5086CB9B 507219EE 95DB113A 917678B2
    // ct     73BED6B8 E3C1743B 7116E69E 22229516
    // ct     3FF1CAA1 681FAC09 120ECA30 7586E1A7

unsigned TimerLap() {
    static unsigned int previousSnap;
    unsigned int currentSnap, ret;
    currentSnap = Timer_A_getCounterValue(TIMER_A1_BASE);
    ret = (currentSnap - previousSnap);
    previousSnap = currentSnap;
    return ret;
}

volatile uint8_t IV[16]        = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
volatile uint8_t Data[64]      = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
                                   0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
                                   0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
                                   0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
uint8_t CipherKey[16]          = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

volatile uint8_t DataAESencrypted[64];
volatile uint8_t DataAESdecrypted[64];

volatile uint16_t Cycles[16];

int main(void) {
    WDTCTL = WDTPW | WDTHOLD;

    Timer_A_initContinuousModeParam initContParam = {0};
    initContParam.clockSource = TIMER_A_CLOCKSOURCE_SMCLK;
    initContParam.clockSourceDivider = TIMER_A_CLOCKSOURCE_DIVIDER_1;
    initContParam.timerInterruptEnable_TAIE = TIMER_A_TAIE_INTERRUPT_DISABLE;
    initContParam.timerClear = TIMER_A_DO_CLEAR;
    initContParam.startTimer = false;
    Timer_A_initContinuousMode(TIMER_A1_BASE, &initContParam);
    Timer_A_startCounter(TIMER_A1_BASE, TIMER_A_CONTINUOUS_MODE );

    //------------------------------ Encryption

    // select encryption
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_0;

    // select key length 128 bit
    AESACTL0 = (AESACTL0 & ~AESKL) | AESKL_0;

    TimerLap();
    Cycles[0] = TimerLap();

    TimerLap();
    uint8_t i;
    for (i=0; i<8; i++)
        AESAKEY = ((uint16_t *) CipherKey)[i];
    Cycles[1] = TimerLap();

    TimerLap();
    // load IV
    for (i=0; i<8; i++)
        AESAXIN = ((uint16_t *) IV)[i];
    Cycles[2] = TimerLap();

    uint16_t k;
    for (k=0; k<4; k++) {
        TimerLap();

        for (i=0; i<8; i++)
            AESAXDIN = ((uint16_t *) Data)[i + (k & 3) * 8];

        while (AESASTAT & AESBUSY) ;

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESencrypted)[i + (k & 3) * 8] = AESADOUT;

        Cycles[3 + (k & 3)] = TimerLap();
    }

    //------------------------------ Decryption

    // Reset AES
    AESACTL0=AESSWRST;

    // select key length 128 bit
    AESACTL0 = (AESACTL0 & ~AESKL) | AESKL_0;

    TimerLap();

    // select decryption (generate roundkeys)
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_2;

    // Load Key
    for (i=0; i<8; i++)
        AESAKEY = ((uint16_t *) CipherKey)[i];
    while (AESASTAT & AESBUSY) ;

    // select decryption (use offline roundkeys)
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_3;

    Cycles[7] = TimerLap();

    AESASTAT |= AESKEYWR;

    for (k=0; k<4; k++) {

        TimerLap();

        // load previous ciphertext or IV
        for (i=0; i<8; i++)
            AESAXIN = k ? ((uint16_t *) DataAESencrypted)[i+(k-1)*8] : ((uint16_t *) IV)[i];

        for (i=0; i<8; i++)
            AESADIN = ((uint16_t *) DataAESencrypted)[i + (k & 3) * 8];

        while (AESASTAT & AESBUSY) ;

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESdecrypted)[i + (k & 3) * 8] = AESADOUT;

        Cycles[8 + (k & 3)] = TimerLap();

    }


    // continuous decryption

    // for GPIO LED
    P1OUT &= ~BIT0;                         // Clear P1.0 output latch for a defined power-on state
    P1DIR |= BIT0;                          // Set P1.0 to output direction
    PM5CTL0 &= ~LOCKLPM5;                   // Disable the GPIO power-on default high-impedance mode
                                            // to activate previously configured port settings
    while (1) {

        for (k=0; k<1024; k++) {

            for (i=0; i<8; i++)
                AESADIN = ((uint16_t *) DataAESencrypted)[i + (k & 3) * 8];

            while (AESASTAT & AESBUSY) ;

            // load previous ciphertext or IV
            for (i=0; i<8; i++)
                AESAXIN = k ? ((uint16_t *) DataAESencrypted)[i+(k-1)*8] : ((uint16_t *) IV)[i];

            for (i=0; i<8; i++)
                ((uint16_t *) DataAESdecrypted)[i + (k & 3) * 8] = AESADOUT;

        }

        for (k=0; k<1024; k++) {
           P1OUT ^= BIT0;                      // Toggle LED
           __delay_cycles(100);
           P1OUT ^= BIT0;                      // Toggle LED

           __delay_cycles(1000);
        }

    }

}
