#include <msp430.h>
#include <stdint.h>
#include "driverlib/driverlib.h"

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

uint8_t CipherKey[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
volatile uint8_t IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

#define NUMBLOCKS 8

volatile uint8_t Data[16*NUMBLOCKS];
volatile uint8_t DataAESencrypted[16*NUMBLOCKS];
volatile uint8_t DataAESdecrypted[16*NUMBLOCKS];

volatile uint8_t MData[16]     = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };

volatile uint16_t Cycles[10];

// DEMO AND PERF EVAL OF CBC AES-128 ENCRYPTION
    // iv     00010203 04050607 08090A0B 0C0D0E0F
    // key    2B7E1516 28AED2A6 ABF71588 09CF4F3C
    // pt     6BC1BEE2 2E409F96 E93D7E11 7393172A
    // ct     7649ABAC 8119B246 CEE98E9B 12E9197D

int main(void) {
    WDTCTL = WDTPW | WDTHOLD;

    initTimer();

    uint16_t i;
    for (i=0; i<NUMBLOCKS; i++) {
        memcpy(Data + i*16, MData, 16);
    }

    TimerLap();
    Cycles[0] = TimerLap();

    //----------------------- Encryption

    TimerLap();

    // Reset AES
    AESACTL0=AESSWRST;

    // select encryption
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_0;

    // select key length 128 bit
    AESACTL0 = (AESACTL0 & ~AESKL) | AESKL_0;

    // select CBC
    AESACTL0 = (AESACTL0 & ~AESCM) | AESCM__CBC;

    // enable DMA
    AESACTL0 = (AESACTL0) | AESCMEN__ENABLE;

    // Load Key
    for (i=0; i<8; i++)
        AESAKEY = ((uint16_t *) CipherKey)[i];

    // Load IV
    for (i=0; i<8; i++)
        AESAXIN = ((uint16_t *) IV)[i];

    // DMA trigger source           AES Trigger
    //      11                          0
    //      12                          1
    //      13                          2

    // DMA Triggers
    DMACTL0 = DMA0TSEL_11 | DMA1TSEL_12;

    // Configure Channel 0
    DMA0CTL = DMADT_0 | DMALEVEL | DMASRCINCR_0 | DMADSTINCR_3;

    // Channel 0 Source Address
    __data20_write_long((unsigned long)&DMA0SA, (unsigned long)&AESADOUT);

    // Channel 0 DestinationAddress
    __data20_write_long((unsigned long)&DMA0DA, (unsigned long)DataAESencrypted);

    // Channel 0 Size
    DMA0SZ = NUMBLOCKS*8;

    // Enable Channel 0
    DMA0CTL |= DMAEN;

    // Configure Channel 1
    DMA1CTL = DMADT_0 | DMALEVEL | DMASRCINCR_3 | DMADSTINCR_0;

    // Channel 1 Source Address
    __data20_write_long((unsigned long)&DMA1SA, (unsigned long)Data);

    // Channel 1 Destination Address
    __data20_write_long((unsigned long)&DMA1DA, (unsigned long)&AESAXDIN);

    // Channel 1 Size
    DMA1SZ = NUMBLOCKS*8;

    // Enable Channel 1
    DMA1CTL |= DMAEN;

    TimerLap();

    AESACTL1 = NUMBLOCKS;

    while (!(DMA0CTL & DMAIFG)) ;
    DMAIV |= 0;

    Cycles[1] = TimerLap(); // 8 Blocks

    // Disable DMA
    DMA0CTL = DMA0CTL & (~DMAEN);
    DMA1CTL = DMA1CTL & (~DMAEN);

    //----------------------- Decryption

    // Reset AES
    AESACTL0=AESSWRST;

    // select key length 128 bit
    AESACTL0 = (AESACTL0 & ~AESKL) | AESKL_0;

    // select decryption
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_2;

    // Load Key
    for (i=0; i<8; i++)
        AESAKEY = ((uint16_t *) CipherKey)[i];
    while (AESASTAT & AESBUSY) ;

    // select decryption (use offline roundkeys)
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_3;

    // select CBC
    AESACTL0 = (AESACTL0 & ~AESCM) | AESCM__CBC;

    // enable DMA
    AESACTL0 = (AESACTL0) | AESCMEN__ENABLE;

    AESASTAT|=AESKEYWR;

    // DMA Triggers
    DMACTL0 = DMA0TSEL_11 | DMA1TSEL_12;  // AES Trigger 0 and 1
    DMACTL1 = DMA2TSEL_13;                // AES Trigger 2

    // Configure Channel 0
    DMA0CTL = DMADT_0 | DMALEVEL | DMASRCINCR_3 | DMADSTINCR_0;

    // Channel 0 Source Address
    __data20_write_long((unsigned long)&DMA0SA, (unsigned long) IV);

    // Channel 0 DestinationAddress
    __data20_write_long((unsigned long)&DMA0DA, (unsigned long)&AESAXIN);

    // Channel 0 Size
    DMA0SZ = 8;

    // Enable Channel 0
    DMA0CTL |= DMAEN;

    // Configure Channel 1
    DMA1CTL = DMADT_0 | DMALEVEL | DMASRCINCR_0 | DMADSTINCR_3;

    // Channel 1 Source Address
    __data20_write_long((unsigned long)&DMA1SA, (unsigned long)&AESADOUT);

    // Channel 1 Destination Address
    __data20_write_long((unsigned long)&DMA1DA, (unsigned long)DataAESdecrypted);

    // Channel 1 Size
    DMA1SZ = NUMBLOCKS*8;

    // Enable Channel 1
    DMA1CTL |= DMAEN;

    // Configure Channel 2
    DMA2CTL=DMADT_0 | DMALEVEL | DMASRCINCR_3 | DMADSTINCR_0;

    // Channel 2 Source Address
    __data20_write_long((unsigned long)&DMA2SA, (unsigned long)DataAESencrypted);

    // Channel 2 Destination Address
    __data20_write_long((unsigned long)&DMA2DA, (unsigned long)&AESADIN);

    // Channel 2 Size
    DMA2SZ = NUMBLOCKS*8;

    // Enable Channel 2
    DMA2CTL |= DMAEN;

    // Start AES
    AESACTL1 = NUMBLOCKS;

    // Wait for end of first block (IV)
    while(!(DMA0CTL & DMAIFG));

    // Configure Channel 0
    DMA0CTL = DMADT_0 | DMALEVEL | DMASRCINCR_3 | DMADSTINCR_0;

    // Channel 0 Source Address
    __data20_write_long((unsigned long)&DMA0SA, (unsigned long)DataAESencrypted);

    // Channel 0 Destination Address
    __data20_write_long((unsigned long)&DMA0DA, (unsigned long)&AESAXIN);

    TimerLap();

    // Channel 0 Size
    DMA0SZ = (NUMBLOCKS-1)*8;

    // Enable Channel 0
    DMA0CTL |= DMAEN;

    // Wait for end of DMA
    while(!(DMA1CTL & DMAIFG));

    Cycles[2] = TimerLap(); // time for seven blocks

    // Disable DMA
    DMA0CTL = DMA0CTL & (~DMAEN);
    DMA1CTL = DMA1CTL & (~DMAEN);
    DMA2CTL = DMA2CTL & (~DMAEN);

    // for GPIO LED
    P1OUT &= ~BIT0;                         // Clear P1.0 output latch for a defined power-on state
    P1DIR |= BIT0;                          // Set P1.0 to output direction
    PM5CTL0 &= ~LOCKLPM5;                   // Disable the GPIO power-on default high-impedance mode
                                            // to activate previously configured port settings
    P1OUT = 0; // clear LED

    AESACTL0=AESSWRST;
    AESACTL0 = (AESACTL0 & ~AESOP) | AESOP_0;
    AESACTL0 = (AESACTL0 & ~AESKL) | AESKL_0;
    AESACTL0 = (AESACTL0 & ~AESCM) | AESCM__CBC;
    AESACTL0 = (AESACTL0) | AESCMEN__ENABLE;
    for (i=0; i<8; i++)
        AESAKEY = ((uint16_t *) CipherKey)[i];
    for (i=0; i<8; i++)
        AESAXIN = ((uint16_t *) IV)[i];

    uint16_t k;
    while (1) {

        for (k=0; k<1024/NUMBLOCKS; k++) {

            DMACTL0 = DMA0TSEL_11 | DMA1TSEL_12;
            DMA0CTL = DMADT_0 | DMALEVEL | DMASRCINCR_0 | DMADSTINCR_3;
            __data20_write_long((unsigned long)&DMA0SA, (unsigned long)&AESADOUT);
            __data20_write_long((unsigned long)&DMA0DA, (unsigned long)DataAESencrypted);
            DMA0SZ = NUMBLOCKS*8;
            DMA0CTL |= DMAEN;
            DMA1CTL = DMADT_0 | DMALEVEL | DMASRCINCR_3 | DMADSTINCR_0;
            __data20_write_long((unsigned long)&DMA1SA, (unsigned long)Data);
            __data20_write_long((unsigned long)&DMA1DA, (unsigned long)&AESAXDIN);
            DMA1SZ = NUMBLOCKS*8;
            DMA1CTL |= DMAEN;
            AESACTL1 = NUMBLOCKS;

            while (!(DMA0CTL & DMAIFG)) ;
            DMAIV |= 0;

            DMA0CTL = DMA0CTL & (~DMAEN);
            DMA1CTL = DMA1CTL & (~DMAEN);

            DMACTL0 = DMA0TSEL_11 | DMA1TSEL_12;
        }

        for (k=0; k<1024; k++) {
           P1OUT ^= BIT0;                      // Toggle LED
           __delay_cycles(100);
           P1OUT ^= BIT0;                      // Toggle LED

           __delay_cycles(1000);
        }

    }



}
