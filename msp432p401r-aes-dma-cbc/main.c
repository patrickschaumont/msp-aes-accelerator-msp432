#include <ti/devices/msp432p4xx/inc/msp432p401r.h>
#include <ti/devices/msp432p4xx/driverlib/driverlib.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

unsigned TimerLap() {
    static unsigned int previousSnap;
    unsigned int currentSnap, ret;
    currentSnap = Timer32_getValue(TIMER32_0_BASE);
    ret = (previousSnap - currentSnap);
    previousSnap = currentSnap;
    return ret;
}

volatile int isFinished = 0;
volatile int decryptiondemo = 0;
#if defined(__TI_COMPILER_VERSION__)
#pragma DATA_ALIGN(MSP_EXP432P401RLP_DMAControlTable, 1024)
#elif defined(__IAR_SYSTEMS_ICC__)
#pragma data_alignment=1024
#elif defined(__GNUC__)
__attribute__ ((aligned (1024)))
#elif defined(__CC_ARM)
__align(1024)
#endif
    uint8_t controlTable[256];

uint8_t IV[16]        = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t CipherKey[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

#define NUMBLOCKS 64

volatile uint8_t Data[16*NUMBLOCKS];
volatile uint8_t DataAESencrypted[16*NUMBLOCKS];
volatile uint8_t DataAESdecrypted[16*NUMBLOCKS];

volatile uint8_t MData[16]     = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };


void DMA_INT1_IRQHandler(void) {
    if (decryptiondemo) {
        DMA_clearInterruptFlag(0);
        DMA_disableChannel(0);
        DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH0_AESTRIGGER0,
                               UDMA_MODE_BASIC,
                               (void*) DataAESencrypted,
                               (void*) &AES256->XIN,
                               (NUMBLOCKS-1)*8);
        DMA_enableChannel(0);
        decryptiondemo = 0;
    } else {
        isFinished = 1;
    }
}

// DEMO AND PERF EVAL OF CBC AES-128 ENCRYPTION

    // iv   00010203 04050607 08090A0B 0C0D0E0F
    // key  2B7E1516 28AED2A6 ABF71588 09CF4F3C

    // pt     6BC1BEE2 2E409F96 E93D7E11 7393172A

    // ct     7649ABAC 8119B246 CEE98E9B 12E9197D

void printData(uint8_t *d, uint32_t l) {
    uint32_t i;
    for (i=0; i<l; i++) {
        printf("%2x ", d[i]);
        if (((i + 1) % 16) == 0)
            printf("\n");
    }
}


void main(void) {
    unsigned cycles;

    WDT_A_holdTimer();

    Interrupt_disableMaster();

    // Timer Initialization
    Timer32_initModule(TIMER32_0_BASE,
                       TIMER32_PRESCALER_1,
                       TIMER32_32BIT,
                       TIMER32_FREE_RUN_MODE);
    Timer32_startTimer(TIMER32_BASE, false);

    uint32_t i;
    for (i=0; i<NUMBLOCKS; i++) {
        memcpy(Data + i*16, MData, 16);
    }

    //---------- encryption
    decryptiondemo = 0;

    // reset AES state
    AES256->CTL0 |= AES256_CTL0_SWRST;

    // select encryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_0;

    // select CBC
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_CM_MASK) | AES256_CTL0_CM__CBC;

    // enable DMA trigger
    AES256->CTL0 = (AES256->CTL0) | AES256_CTL0_CMEN;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    // load KEY
    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];

    // load IV
    for (i=0; i<8; i++)
        AES256->XIN = ((uint16_t *) IV)[i];

    DMA_enableModule();
    DMA_setControlBase(controlTable);

    // DMA Channel 0 -> AES Trigger 0
    // AES256->DOUT to AESencrypted
    DMA_setChannelControl(UDMA_PRI_SELECT | DMA_CH0_AESTRIGGER0,
                          UDMA_SIZE_16 | UDMA_SRC_INC_NONE | UDMA_DST_INC_16 | UDMA_ARB_8);
    DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH0_AESTRIGGER0,
                          UDMA_MODE_BASIC,
                          (void*) &AES256->DOUT,
                          DataAESencrypted,
                          NUMBLOCKS*8);

    // DMA Channel 1 -> AES Trigger 1
    // plaintext to AES256->DIN
    DMA_setChannelControl(UDMA_PRI_SELECT | DMA_CH1_AESTRIGGER1,
                          UDMA_SIZE_16 | UDMA_SRC_INC_16 | UDMA_DST_INC_NONE | UDMA_ARB_8);
    DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH1_AESTRIGGER1,
                           UDMA_MODE_BASIC,
                           (void*) Data,
                           (void*) &AES256->XDIN,
                           NUMBLOCKS*8);

    // Interrupt system
    DMA_assignInterrupt(DMA_INT1, 0);
    Interrupt_enableInterrupt(INT_DMA_INT1);
    DMA_assignChannel(DMA_CH0_AESTRIGGER0);
    DMA_assignChannel(DMA_CH1_AESTRIGGER1);
    DMA_clearInterruptFlag(0);
    DMA_clearInterruptFlag(1);
    Interrupt_enableMaster();

    DMA_enableChannel(1);
    DMA_enableChannel(0);

    TimerLap();

    AES256->CTL1 = NUMBLOCKS;

    while (!isFinished) ; // wait

    cycles = TimerLap();

    isFinished = 0;

    Interrupt_disableMaster();

    printf("DMA Complete - CBC Encrypting %d Blocks %d cycles (per block %d cycles)\n", NUMBLOCKS, cycles, cycles/NUMBLOCKS);
    for (i=0; i<4; i++)
        printData(DataAESencrypted + i*16, 16);

    //---------- decryption
    decryptiondemo = 1;

    // reset AES state
    AES256->CTL0 |= AES256_CTL0_SWRST;

    // select decryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_2;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    // load KEY
    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];

    // run keyschedule
    while (AES256->STAT & AES256_STAT_BUSY) ;

    // select CBC
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_CM_MASK) | AES256_CTL0_CM__CBC;

    // select decryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_3;

    // enable DMA trigger
    AES256->CTL0 = (AES256->CTL0) | AES256_CTL0_CMEN;

    // use previous key
    AES256->STAT |= AES256_STAT_KEYWR;

    DMA_enableModule();
    DMA_setControlBase(controlTable);

    // DMA Channel 0 -> AES Trigger 0
    // IV to AESAXIN
    DMA_setChannelControl(UDMA_PRI_SELECT | DMA_CH0_AESTRIGGER0,
                          UDMA_SIZE_16 | UDMA_SRC_INC_16 | UDMA_DST_INC_NONE | UDMA_ARB_8);
    DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH0_AESTRIGGER0,
                          UDMA_MODE_BASIC,
                          (void*) IV,
                          (void*) &AES256->XIN,
                          8);

    // DMA Channel 1 -> AES Trigger 1
    // AES256->DOUT to plaintext
    DMA_setChannelControl(UDMA_PRI_SELECT | DMA_CH1_AESTRIGGER1,
                          UDMA_SIZE_16 | UDMA_SRC_INC_NONE | UDMA_DST_INC_16 | UDMA_ARB_8);
    DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH1_AESTRIGGER1,
                           UDMA_MODE_BASIC,
                           (void*) &AES256->DOUT,
                           (void*) DataAESdecrypted,
                           NUMBLOCKS*8);

    // DMA Channel 2 -> AES Trigger 2
    // ciphertext to AES256->DIN
    DMA_setChannelControl(UDMA_PRI_SELECT | DMA_CH2_AESTRIGGER2,
                          UDMA_SIZE_16 | UDMA_SRC_INC_16 | UDMA_DST_INC_NONE | UDMA_ARB_8);
    DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH2_AESTRIGGER2,
                           UDMA_MODE_BASIC,
                           (void*) DataAESencrypted ,
                           (void*) &AES256->DIN,
                           NUMBLOCKS*8);

    // Interrupt system
    DMA_assignInterrupt(DMA_INT1, 0);
    Interrupt_enableInterrupt(INT_DMA_INT1);
    DMA_assignChannel(DMA_CH0_AESTRIGGER0);
    DMA_assignChannel(DMA_CH1_AESTRIGGER1);
    DMA_assignChannel(DMA_CH2_AESTRIGGER2);
    DMA_clearInterruptFlag(0);
    DMA_clearInterruptFlag(1);
    DMA_clearInterruptFlag(2);
    Interrupt_enableMaster();

    DMA_enableChannel(2);
    DMA_enableChannel(1);
    DMA_enableChannel(0);

    TimerLap();

    AES256->CTL1 = NUMBLOCKS;

    while (!isFinished) ; // wait

    isFinished = 0;

    cycles = TimerLap();

    printf("DMA Complete - CBC Decrypting %d Blocks %d cycles (per block %d cycles)\n", NUMBLOCKS, cycles, cycles/NUMBLOCKS);
    for (i=0; i<4; i++)
        printData(DataAESdecrypted + i*16, 16);

}


