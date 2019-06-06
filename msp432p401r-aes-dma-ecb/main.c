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

volatile int isFinished = 0;

void DMA_INT1_IRQHandler(void) {
   isFinished = 1;
}


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

uint8_t CipherKey[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};

#define NUMBLOCKS 64

volatile uint8_t Data[16*NUMBLOCKS];
volatile uint8_t DataAESencrypted[16*NUMBLOCKS];
volatile uint8_t DataAESdecrypted[16*NUMBLOCKS];

volatile uint8_t MData[16]     = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };

// DEMO AND PERF EVAL OF ECB AES-128 ENCRYPTION

// key    2B7E1516 28AED2A6 ABF71588 09CF4F3C
// pt     6BC1BEE2 2E409F96 E93D7E11 7393172A
// ct     3AD77BB4 0D7A3660 A89ECAF3 2466EF97

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

    // select encryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_0;

    // select ECB
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_CM_MASK) | AES256_CTL0_CM__ECB;

    // enable DMA trigger
    AES256->CTL0 = (AES256->CTL0) | AES256_CTL0_CMEN;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];

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
                           (void*) &AES256->DIN,
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

    while (!isFinished)
        PCM_gotoLPM0InterruptSafe(); // wait

    cycles = TimerLap();

    isFinished = 0;

    Interrupt_disableMaster();

    printf("DMA Complete - Encrypting %d Blocks %d cycles (per block %d cycles)\n", NUMBLOCKS, cycles, cycles/NUMBLOCKS);
    for (i=0; i<4; i++)
        printData(DataAESencrypted + i*16, 16);

    //---------- decryption

    // select decryption
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_OP_MASK) | AES256_CTL0_OP_1;

    // select ECB
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_CM_MASK) | AES256_CTL0_CM__ECB;

    // enable DMA trigger
    AES256->CTL0 = (AES256->CTL0) | AES256_CTL0_CMEN;

    // key length is 128 bit
    AES256->CTL0 = (AES256->CTL0 & ~AES256_CTL0_KL_MASK) | AES256_CTL0_KL__128BIT;

    for (i=0; i<8; i++)
        AES256->KEY = ((uint16_t *) CipherKey)[i];

    DMA_enableModule();
    DMA_setControlBase(controlTable);

    // DMA Channel 0 -> AES Trigger 0
    // AES256->DOUT to AESencrypted
    DMA_setChannelControl(UDMA_PRI_SELECT | DMA_CH0_AESTRIGGER0,
                          UDMA_SIZE_16 | UDMA_SRC_INC_NONE | UDMA_DST_INC_16 | UDMA_ARB_8);
    DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH0_AESTRIGGER0,
                          UDMA_MODE_BASIC,
                          (void*) &AES256->DOUT,
                          DataAESdecrypted,
                          NUMBLOCKS*8);

    // DMA Channel 1 -> AES Trigger 1
    // plaintext to AES256->DIN
    DMA_setChannelControl(UDMA_PRI_SELECT | DMA_CH1_AESTRIGGER1,
                          UDMA_SIZE_16 | UDMA_SRC_INC_16 | UDMA_DST_INC_NONE | UDMA_ARB_8);
    DMA_setChannelTransfer(UDMA_PRI_SELECT | DMA_CH1_AESTRIGGER1,
                           UDMA_MODE_BASIC,
                           (void*) DataAESencrypted,
                           (void*) &AES256->DIN,
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

    while (!isFinished)
        PCM_gotoLPM0InterruptSafe(); // wait

    cycles = TimerLap();

    isFinished = 0;

    Interrupt_disableMaster();

    printf("DMA Complete - Decrypting %d Blocks %d cycles (per block %d cycles)\n", NUMBLOCKS, cycles, cycles/NUMBLOCKS);
    for (i=0; i<4; i++)
        printData(DataAESdecrypted + i*16, 16);

}


