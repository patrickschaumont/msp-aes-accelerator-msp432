#include <ti/devices/msp432p4xx/inc/msp432p401r.h>
#include <ti/devices/msp432p4xx/driverlib/driverlib.h>
#include "aes.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

unsigned TimerLap() {
    static unsigned int previousSnap;
    unsigned int currentSnap, ret;
    currentSnap = Timer32_getValue(TIMER32_0_BASE);
    ret = (previousSnap - currentSnap);
    previousSnap = currentSnap;
    return ret;
}

void printData(uint8_t *d, uint32_t l) {
    uint32_t i;
    for (i=0; i<l; i++) {
        printf("%2x ", d[i]);
        if (((i + 1) % 16) == 0)
            printf("\n");
    }
}

void printData16(uint8_t *d, uint32_t l) {
    uint32_t i;
    for (i=0; i<l; i++) {
        printf("%2x ", ((uint16_t *)d)[i]);
        if (((i + 1) % 16) == 0)
            printf("\n");
    }
}

uint8_t Data[64]      = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
                          0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
                          0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
                          0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
uint8_t CipherKey[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

uint32_t Cycles[16];

void main(void) {
    WDT_A->CTL = WDT_A_CTL_PW | WDT_A_CTL_HOLD;

    // Timer Initialization
    Timer32_initModule(TIMER32_0_BASE,
                       TIMER32_PRESCALER_1,
                       TIMER32_32BIT,
                       TIMER32_FREE_RUN_MODE);
    Timer32_startTimer(TIMER32_BASE, false);

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

    uint8_t DataAESencrypted[64];

    struct AES_ctx SWAES;

    TimerLap();
    AES_init_ctx(&SWAES, CipherKey);
    Cycles[0] = TimerLap();

    uint32_t k;
    for (k=0; k<4; k++) {
        TimerLap();
        AES_ECB_encrypt(&SWAES, Data + k*16);
        Cycles[1 + k] = TimerLap();
    }
    memcpy(DataAESencrypted, Data, 64);

    printData(DataAESencrypted, 16);
    printData(DataAESencrypted + 16, 16);
    printData(DataAESencrypted + 32, 16);
    printData(DataAESencrypted + 48, 16);

    for (k=0; k<4; k++) {
        TimerLap();
        AES_ECB_decrypt(&SWAES, DataAESencrypted + k*16);
        Cycles[5 + k] = TimerLap();
    }

    printData(DataAESencrypted, 16);
    printData(DataAESencrypted + 16, 16);
    printData(DataAESencrypted + 32, 16);
    printData(DataAESencrypted + 48, 16);

    for (k=0; k<9; k++)
        printf("Cycles %d = %d\n", k, Cycles[k]);

}
