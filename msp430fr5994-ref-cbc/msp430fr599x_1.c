#include <msp430.h>
#include <stdint.h>
#include "driverlib/driverlib.h"

#include "aes.h"

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

static uint32_t currentInt;
static uint32_t currentIntTotal;

uint32_t TimerLap() {
    static unsigned int previousSnap;
    unsigned currentSnap;
    uint32_t ret;
    Timer_A_disableInterrupt(TIMER_A1_BASE);
    currentSnap = Timer_A_getCounterValue(TIMER_A1_BASE);
    if (currentSnap < previousSnap)
        ret = ((uint16_t) (currentSnap - previousSnap)) + ((currentInt-1) << 16);
    else
       ret = ((uint16_t) (currentSnap - previousSnap)) + (currentInt << 16);
    currentInt = 0;
    previousSnap = currentSnap;
    Timer_A_enableInterrupt(TIMER_A1_BASE);
    return ret;
}

void initTimer() {
    Timer_A_initContinuousModeParam initContParam = {0};
    initContParam.clockSource = TIMER_A_CLOCKSOURCE_SMCLK;
    initContParam.clockSourceDivider = TIMER_A_CLOCKSOURCE_DIVIDER_1;
    initContParam.timerInterruptEnable_TAIE = TIMER_A_TAIE_INTERRUPT_ENABLE;
    initContParam.timerClear = TIMER_A_DO_CLEAR;
    initContParam.startTimer = false;
    Timer_A_initContinuousMode(TIMER_A1_BASE, &initContParam);
    Timer_A_startCounter(TIMER_A1_BASE, TIMER_A_CONTINUOUS_MODE );
    currentInt = 0;
    currentIntTotal = 0;
    Timer_A_enableInterrupt(TIMER_A1_BASE);
}

#pragma vector=TIMER1_A1_VECTOR
__interrupt void TIMER1_A1_ISR (void) {
    //Any access, read or write, of the TAIV register automatically resets the
    //highest "pending" interrupt flag
    switch ( __even_in_range(TA1IV,14) ){
        case  0: break;                          //No interrupt
        case  2: break;                          //CCR1 not used
        case  4: break;                          //CCR2 not used
        case  6: break;                          //CCR3 not used
        case  8: break;                          //CCR4 not used
        case 10: break;                          //CCR5 not used
        case 12: break;                          //CCR6 not used
        case 14:
            //Toggle P1.0                    // overflow
            currentInt = currentInt + 1;
            currentIntTotal = currentIntTotal + 1;
            break;
        default: break;
    }
}

uint32_t Cycles[16];

uint8_t IV[16]        = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t Data[64]      = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
                          0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
                          0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
                          0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
uint8_t CipherKey[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

uint8_t DataAESencrypted[64];

int main(void) {
    WDTCTL = WDTPW | WDTHOLD;

    initTimer();
    __bis_SR_register(GIE);

    struct AES_ctx SWAES;

    TimerLap();
    Cycles[0] = TimerLap();

    TimerLap();
    AES_init_ctx_iv(&SWAES, CipherKey, IV);
    Cycles[1] = TimerLap();

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

    TimerLap();
    AES_CBC_encrypt_buffer(&SWAES, Data, 64);
    Cycles[2] = TimerLap();

    memcpy(DataAESencrypted, Data, 64);

    AES_init_ctx_iv(&SWAES, CipherKey, IV);

    TimerLap();
    AES_CBC_decrypt_buffer(&SWAES, DataAESencrypted, 64);
    Cycles[3] = TimerLap();

    while (1)
        Cycles[5] = currentIntTotal;
}
