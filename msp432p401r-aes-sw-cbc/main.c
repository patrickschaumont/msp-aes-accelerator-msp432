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

    uint8_t IV[16]        = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
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

    TimerLap();
    // load IV
    for (i=0; i<8; i++)
        AES256->XIN = ((uint16_t *) IV)[i];
    cycles = TimerLap();

    printf("Cycles IV Load %d\n", cycles);

    // load plaintext
    uint32_t k;
    for (k=0; k<4; k++) {

        TimerLap();

        for (i=0; i<8; i++)
            AES256->XDIN = ((uint16_t *) Data)[i+k*8];

        while (AES256->STAT & AES256_STAT_BUSY) ;

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESencrypted)[i] = AES256->DOUT;

        cycles = TimerLap();

        printf("Cycles Encr %d\n", cycles);

        printData(DataAESencrypted, 16);
    }

    TimerLap();

    // load IV
    for (i=0; i<8; i++)
        AES256->XIN = ((uint16_t *) Data)[i+k*8];

    uint32_t l;
    for (l=0; l<256; l++) {
        for (k=0; k<4; k++) {


            for (i=0; i<8; i++)
                AES256->XDIN = ((uint16_t *) Data)[i+k*8];

            while (AES256->STAT & AES256_STAT_BUSY) ;

            for (i=0; i<8; i++)
                ((uint16_t *) DataAESencrypted)[i] = AES256->DOUT;

        }
    }
    cycles = TimerLap();

    printf("Cycles 1K CBC Encryptions %d\n", cycles);

    //------------------------------------------------

    // ct     7649ABAC8119B246CEE98E9B12E9197D
    // ct     5086CB9B507219EE95DB113A917678B2
    // ct     73BED6B8E3C1743B7116E69E22229516
    // ct     3FF1CAA1681FAC09120ECA307586E1A7

    uint8_t CData[64]     = { 0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
                              0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
                              0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
                              0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7};

    uint8_t DataAESdecrypted[16];

    // select decryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_1;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];

    // load plaintext
    for (k=0; k<4; k++) {

        for (i=0; i<8; i++)
            AES256->DIN = ((uint16_t *) CData)[i+k*8];

        while (AES256->STAT & AES256_STAT_BUSY) ;

        // load previous ciphertext or IV
        for (i=0; i<8; i++)
            AES256->XIN = k ? ((uint16_t *) CData)[i+(k-1)*8] : ((uint16_t *) IV)[i];

        for (i=0; i<8; i++)
            ((uint16_t *) DataAESdecrypted)[i] = AES256->DOUT;

        printData(DataAESdecrypted, 16);
    }

    TimerLap();

    // select decryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_1;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];

    for (l=0; l<256; l++) {
        for (k=0; k<4; k++) {
            for (i=0; i<8; i++)

                for (i=0; i<8; i++)
                    AES256->DIN = ((uint16_t *) CData)[i+k*8];

                while (AES256->STAT & AES256_STAT_BUSY) ;

                // load previous ciphertext or IV
                for (i=0; i<8; i++)
                    AES256->XIN = k ? ((uint16_t *) CData)[i+(k-1)*8] : ((uint16_t *) IV)[i];

                for (i=0; i<8; i++)
                    ((uint16_t *) DataAESdecrypted)[i] = AES256->DOUT;
        }
    }
    cycles = TimerLap();

    printf("Cycles 1K CBC Decryptions %d\n", cycles);




}
