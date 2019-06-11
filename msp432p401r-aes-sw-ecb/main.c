#include <ti/devices/msp432p4xx/inc/msp432p401r.h>
#include <ti/devices/msp432p4xx/driverlib/driverlib.h>

#include <stdint.h>
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

    uint8_t Data[64]      = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
                              0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
                              0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
                              0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
    uint8_t CipherKey[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

    uint8_t DataAESencrypted[16];

    // select encryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_0;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    unsigned cycles;
    TimerLap();
    cycles = TimerLap();
    printf("Cycles Overhead %d\n", cycles);

    TimerLap();
    uint32_t i;
    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];
    while (AES256->STAT & AES256_STAT_BUSY) ;
    cycles = TimerLap();

    printf("Cycles Key Load %d\n", cycles);

    uint32_t k;
    for (k=0; k<4; k++) {
        TimerLap();
        for (i=0; i<8; i++)
//            AES256->DIN = ((uint16_t *) Data)[i+k*8];
        AES256->DIN = ((uint16_t *) Data)[i];

        while (AES256->STAT & AES256_STAT_BUSY) ;

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESencrypted)[i] = AES256->DOUT;
        cycles = TimerLap();

        printf("Cycles Encryption %d\n", cycles);

        printData(DataAESencrypted, 16);
    }

    TimerLap();
    uint32_t l;
    for (l=0; l<256; l++) {
        for (k=0; k<4; k++) {
            for (i=0; i<8; i++)
                AES256->DIN = ((uint16_t *) Data)[i+k*8];

            while (AES256->STAT & AES256_STAT_BUSY) ;

            for (i=0; i<8; i++)
                ((uint16_t *) DataAESencrypted)[i] = AES256->DOUT;
        }
    }
    cycles = TimerLap();

    printf("Cycles 1K ECB Encryptions %d\n", cycles);

    // ----------------------------- decryption

    uint8_t CData[64]     = { 0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
                              0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
                              0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
                              0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4};

    uint8_t DataAESdecrypted[16];

    // select decryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_1;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];

    for (k=0; k<4; k++) {
        for (i=0; i<8; i++)
            AES256->DIN = ((uint16_t *) CData)[i+k*8];

        while (AES256->STAT & AES256_STAT_BUSY) ;

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESdecrypted)[i] = AES256->DOUT;

        printData(DataAESdecrypted, 16);
    }

    TimerLap();
    for (l=0; l<256; l++) {
        for (k=0; k<4; k++) {
            for (i=0; i<8; i++)
                AES256->DIN = ((uint16_t *) Data)[i+k*8];

            while (AES256->STAT & AES256_STAT_BUSY) ;

            for (i=0; i<8; i++)
                ((uint16_t *) DataAESencrypted)[i] = AES256->DOUT;
        }
    }
    cycles = TimerLap();

    printf("Cycles 1K ECB Decryptions %d\n", cycles);

}
