#include <msp430.h>
#include <stdint.h>
#include "driverlib/driverlib.h"

// DEMO AND PERF EVAL OF ECB AES-128 ENCRYPTION

// key    2B7E1516 28AED2A6 ABF71588 09CF4F3C

// pt     6BC1BEE2 2E409F96 E93D7E11 7393172A
// ct     3AD77BB4 0D7A3660 A89ECAF3 2466EF97

// pt     AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
// ct     F5D3D585 03B9699D E785895A 96FDBAAF

// pt     30C81C46 A35CE411 E5FBC119 1A0A52EF
// ct     43B1CD7F 598ECE23 881B00E3 ED030688

// pt     F69F2445 DF4F9B17 AD2B417B E66C3710
// ct     7B0C785E 27E8AD3F 82232071 04725DD4

unsigned TimerLap() {
    static unsigned int previousSnap;
    unsigned int currentSnap, ret;
    currentSnap = Timer_A_getCounterValue(TIMER_A1_BASE);
    ret = (currentSnap - previousSnap);
    previousSnap = currentSnap;
    return ret;
}

void initTimer() {
    Timer_A_initContinuousModeParam initContParam = {0};
    initContParam.clockSource = TIMER_A_CLOCKSOURCE_SMCLK;
    initContParam.clockSourceDivider = TIMER_A_CLOCKSOURCE_DIVIDER_1;
    initContParam.timerInterruptEnable_TAIE = TIMER_A_TAIE_INTERRUPT_DISABLE;
    initContParam.timerClear = TIMER_A_DO_CLEAR;
    initContParam.startTimer = false;
    Timer_A_initContinuousMode(TIMER_A1_BASE, &initContParam);
    Timer_A_startCounter(TIMER_A1_BASE, TIMER_A_CONTINUOUS_MODE );
}

volatile uint8_t Data[16]      = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
uint8_t CipherKey[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
volatile uint8_t DataAESencrypted[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
volatile uint8_t DataAESdecrypted[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
volatile uint16_t Cycles[10];

int main(void) {
    WDTCTL = WDTPW | WDTHOLD;

    initTimer();

    // -------------------- Encryption

    // Reset AES
    AESACTL0=AESSWRST;

    // select encryption
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_0;

    // select key length 128 bit
    AESACTL0 = (AESACTL0 & ~AESKL) | AESKL_0;

    TimerLap();
    Cycles[0] = TimerLap();

    uint8_t i;
    for (i=0; i<8; i++)
        AESAKEY = ((uint16_t *) CipherKey)[i];
    while (AESASTAT & AESBUSY) ;
    Cycles[1] = TimerLap();

    uint16_t k;
    for (k=0; k<32; k++) {

        TimerLap();

        for (i=0; i<8; i++)
            AESADIN = ((uint16_t *) Data)[i];

        while (AESASTAT & AESBUSY) ;

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESencrypted)[i] = AESADOUT;

        Cycles[2] = TimerLap();
    }

    // -------------------- Decryption

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

    Cycles[6] = TimerLap();

    // select decryption (use offline roundkeys)
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_3;

    AESASTAT |= AESKEYWR;

    for (k=0; k<32; k++) {

        TimerLap();

        for (i=0; i<8; i++)
            AESADIN = ((uint16_t *) DataAESencrypted)[i];

        while (AESASTAT & AESBUSY) ;

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESdecrypted)[i] = AESADOUT;

        Cycles[7 + (k & 3)] = TimerLap();
    }


    // for GPIO LED
    P1OUT &= ~BIT0;                         // Clear P1.0 output latch for a defined power-on state
    P1DIR |= BIT0;                          // Set P1.0 to output direction
    PM5CTL0 &= ~LOCKLPM5;                   // Disable the GPIO power-on default high-impedance mode
                                            // to activate previously configured port settings
    while (1) {

        for (k=0; k<1024; k++) {
           for (i=0; i<8; i++)
             AESADIN = ((uint16_t *) Data)[i];

           while (AESASTAT & AESBUSY) ;

           for (i=0; i<8; i++)
              ((uint16_t *) DataAESencrypted)[i] = AESADOUT;
        }

        P1OUT ^= BIT0;                      // Toggle LED
        __delay_cycles(50000);
           P1OUT ^= BIT0;                      // Toggle LED

        __delay_cycles(50000);
        }


}
