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

uint32_t  TimerLap() {
    static uint32_t  previousSnap;
    uint32_t  currentSnap, ret;
    currentSnap = Timer_A_getCounterValue(TIMER_A1_BASE);
    ret = (currentSnap - previousSnap) + (currentInt << 16);
    previousSnap = currentSnap;
    currentInt   = 0;
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
            break;
        default: break;
    }
}

volatile uint8_t Data[16]             = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A};
uint8_t CipherKey[16]                 = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
volatile uint8_t DataAESencrypted[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
volatile uint32_t Cycles[10];

int main(void) {
    WDTCTL = WDTPW | WDTHOLD;

    initTimer();
    __bis_SR_register(GIE);

    struct AES_ctx SWAES;

    TimerLap();
    AES_init_ctx(&SWAES, CipherKey);
    Cycles[0] = TimerLap();

    TimerLap();
    AES_ECB_encrypt(&SWAES, Data);
    Cycles[1] = TimerLap();
    memcpy(DataAESencrypted, Data, 16);

    TimerLap();
    AES_ECB_decrypt(&SWAES, DataAESencrypted);
    Cycles[2] = TimerLap();

    while (1) ;
}
