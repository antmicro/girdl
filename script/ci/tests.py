#!/bin/env python3

from subprocess import Popen, PIPE
import os

DATA=os.environ['DATA']

def normalize_string(str):

    lines = str.split('\n')
    length = len(str)

    for line in lines:

        if len(line) == 0:
            continue

        stipped = len(line) - len(line.lstrip())

        if stipped == 0:
            continue

        if stipped < length:
            length = stipped

    return "\n".join([line[length:] for line in lines])


def gdb_test(name, setup, test, expect, condition="True"):
    print(f'\n\033[1mTEST: \033[36m{name}\033[0m')

    condition_value = eval(condition, {"exists": os.path.exists})

    if not condition_value:
        print(f'      -- Condition {condition}: {condition_value}')
        print("      \033[1;33mSKIPPED\033[0m")
        return

    try:
        if setup:
            os.system(setup)

        with Popen(['gdb'], stdin=PIPE, stdout=PIPE, stderr=PIPE) as proc:

            proc.stdin.write(test.encode())
            proc.stdin.close()

            out_stderr = proc.stderr.read().decode()
            out_stdout = proc.stdout.read().decode()

            if len(out_stderr) != 0:
                print(f'      -- Standard error: {out_stderr}')

            output = out_stdout.replace('\t', "    ")
            needle = normalize_string(expect)

            if needle in output:
                print("      \033[1;32mPASSED\033[0m")
                return
            else:
                print(f'      -- Substring "{needle} not found in input "{output}"')
    except Exception as e:
        print(f'      -- Exception: {e}')
        pass

    print("      \033[1;31mFAILED\033[0m")

gdb_test(
    name='Check if peripheral types are being exported',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/FT5336.rdl" -q',
    test='add-symbol-file symbols.dwarf\ninfo types',
    expect="""
        (gdb) All defined types:
        
        File symbols.dwarf.c:
            struct FT5336;
            uint8_t
        (gdb)"""
)

gdb_test(
    name='Check if registers are correctly added to the peripheral',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/FT5336.rdl" -q',
    test='add-symbol-file symbols.dwarf\nptype struct FT5336',
    expect="""
        (gdb) type = struct FT5336 {
            uint8_t TouchXHigh;
            uint8_t TouchXLow;
            uint8_t TouchYHigh;
            uint8_t TouchYLow;
            uint8_t TouchWeight;
            uint8_t TouchMisc;
        }
        (gdb)"""
)

gdb_test(
    name='Check if output can be changed',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/FT5336.rdl" -q -o "output.elf"',
    test='add-symbol-file output.elf\ninfo types',
    expect="""
        (gdb) All defined types:

        File output.elf.c:
            struct FT5336;
            uint8_t
        (gdb)"""
)

gdb_test(
    name='Check if SVD imports all peripheral types',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/STM32WL33.svd" -q > /dev/null',
    test='add-symbol-file symbols.dwarf\ninfo types',
    expect="""
        (gdb) All defined types:

        File symbols.dwarf.c:
            struct ADC;
            struct AES;
            struct COMP;
            struct CRC;
            struct DAC;
            struct DBGMCU;
            struct DMA;
            struct DMAMUX;
            struct DYNAMIC_REG;
            struct FLASH_CTRL;
            struct GPIOA;
            struct GPIOB;
            struct I2C1;
            struct I2C2;
            struct IWDG;
            struct LCD;
            struct LCSC;
            struct LPAWUR;
            struct LPUART;
            struct MISC;
            struct MR_SUBG;
            struct PWRC;
            struct RCC;
            struct RETAINED;
            struct RNG;
            struct RTC;
            struct SPI;
            struct SPI3;
            struct STATIC;
            struct STATUS;
            struct SWITCHABLE;
            struct SYSTEM_CTRL;
            struct TIM16;
            struct TIM2;
            struct USART;"""
)

gdb_test(
    name='Check if SVD imports binds peripherals as variables',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/STM32WL33.svd" -q > /dev/null',
    test='add-symbol-file symbols.dwarf\ninfo variables',
    expect="""
        (gdb) All defined variables:

        File symbols.dwarf.c:
            static struct ADC ADC;
            static struct AES AES;
            static struct COMP COMP;
            static struct CRC CRC;
            static struct DAC DAC;
            static struct DBGMCU DBGMCU;
            static struct DMA DMA;
            static struct DMAMUX DMAMUX;
            static struct DYNAMIC_REG DYNAMIC_REG;
            static struct FLASH_CTRL FLASH_CTRL;
            static struct GPIOA GPIOA;
            static struct GPIOB GPIOB;
            static struct I2C1 I2C1;
            static struct I2C2 I2C2;
            static struct IWDG IWDG;
            static struct LCD LCD;
            static struct LCSC LCSC;
            static struct LPAWUR LPAWUR;
            static struct LPUART LPUART;
            static struct MISC MISC;
            static struct MR_SUBG MR_SUBG;
            static struct PWRC PWRC;
            static struct RCC RCC;
            static struct RETAINED RETAINED;
            static struct RNG RNG;
            static struct RTC RTC;
            static struct SPI SPI;
            static struct SPI3 SPI3;
            static struct STATIC STATIC;
            static struct STATUS STATUS;
            static struct SWITCHABLE SWITCHABLE;
            static struct SYSTEM_CTRL SYSTEM_CTRL;
            static struct TIM16 TIM16;
            static struct TIM2 TIM2;
            static struct USART USART;"""
)

gdb_test(
    name='Check if SVD imports registers and fields from peripherals',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/STM32WL33.svd" -q > /dev/null',
    test='add-symbol-file symbols.dwarf\nptype struct RCC',
    expect="""
        (gdb) type = struct RCC {
            struct {
                bits bits_2 : 2;
                bits LSION : 1;
                bits LSIRDY : 1;
                bits LSEON : 1;
                bits LSERDY : 1;
                bits LSEBYP : 1;
                bits LOCKDET_NSTOP : 3;
                bits HSIRDY : 1;
                bits bits_1 : 1;
                bits HSEPLLBUFON : 1;
                bits HSIPLLON : 1;
                bits HSIPLLRDY : 1;
                bits FMRAT : 1;
                bits HSEON : 1;
                bits HSERDY : 1;
                bits bits_14 : 14;
            } CR;
            struct {
                bits LSITRIMEN : 1;
                bits LSITRIMOK : 1;
                bits LSIBW : 4;
                bits bits_10 : 10;
                bits HSITRIMOFFSET : 3;
                bits bits_5 : 5;
                bits HSITRIM : 6;
                bits bits_2 : 2;
            } ICSCR;
            struct {
                bits bits_1 : 1;
                bits HSESEL : 1;
                bits STOPHSI : 1;
                bits HSESEL_STATUS : 1;
                bits bits_1 : 1;
                bits CLKSYSDIV : 3;
                bits CLKSYSDIV_STATUS : 3;
                bits bits_1 : 1;
                bits SMPSDIV : 1;
                bits LPUCLKSEL : 1;
                bits bits_1 : 1;
                bits CLKSLOWSEL : 2;
                bits IOBOOSTEN : 1;
                bits bits_1 : 1;
                bits LCOEN : 1;
                bits bits_2 : 2;
                bits SPI3I2SCLKSEL : 2;
                bits LCOSEL : 2;
                bits MCOSEL : 3;
                bits CCOPRE : 3;
            } CFGR;"""
)

gdb_test(
    name='Check if register fields are being exported',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/SAMD21_Timer.rdl" -q',
    test='add-symbol-file symbols.dwarf\nptype struct SAMD21_Timer',
    expect="""
        (gdb) type = struct SAMD21_Timer {
            struct {
                bits SWRST : 1;
                bits ENABLE : 1;
                bits MODE : 2;
                bits bits_1 : 1;
                bits WAVEGEN : 2;
                bits bits_1 : 1;
            } ControlA0;
            struct {
                bits PRESCALER : 3;
                bits RUNSTDBY : 1;
                bits PRESCSYNC : 2;
                bits bits_2 : 2;
            } ControlA1;
            uint8_t ReadRequest0;
            uint8_t ReadRequest1;
            struct {
                bits DIR : 1;
                bits bits_1 : 1;
                bits ONESHOT : 1;
                bits bits_3 : 3;
                bits CMD : 2;
            } ControlBClear;
            struct {
                bits DIR : 1;
                bits bits_1 : 1;
                bits ONESHOT : 1;
                bits bits_3 : 3;
                bits CMD : 2;
            } ControlBSet;
            uint8_t ControlC;
            uint8_t Reserved0;
            uint8_t DebugControl;
            uint8_t Reserved1;
            uint16_t EventControl;
            struct {
                bits OVF : 1;
                bits ERR : 1;
                bits bits_1 : 1;
                bits SYNCRDY : 1;
                bits MC0 : 1;
                bits MC1 : 1;
                bits bits_2 : 2;
            } InterruptEnableClear;
            struct {
                bits OVF : 1;
                bits ERR : 1;
                bits bits_1 : 1;
                bits SYNCRDY : 1;
                bits MC0 : 1;
                bits MC1 : 1;
                bits bits_2 : 2;
            } InterruptEnableSet;
            struct {
                bits OVF : 1;
                bits ERR : 1;
                bits bits_1 : 1;
                bits SYNCRDY : 1;
                bits MC0 : 1;
                bits MC1 : 1;
                bits bits_2 : 2;
            } InterruptFlags;
            struct {
                bits bits_3 : 3;
                bits STOP : 1;
                bits bits_3 : 3;
                bits SYNCBUSY : 1;
            } Status;
            uint8_t Counter0;
            uint8_t Counter1;
            uint8_t Counter2;
            uint8_t Counter3;
            uint8_t pad_4[5];
            uint8_t ChannelCompareCaptureValue0_0;
            uint8_t ChannelCompareCaptureValue0_1;
            uint8_t ChannelCompareCaptureValue0_2;
            uint8_t ChannelCompareCaptureValue0_3;
            uint8_t ChannelCompareCaptureValue1_0;
            uint8_t ChannelCompareCaptureValue1_1;
            uint8_t ChannelCompareCaptureValue1_2;
            uint8_t ChannelCompareCaptureValue1_3;
        }
        (gdb)"""
)

gdb_test(
    name='Check if no default macro is provided',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl"',
    test='add-symbol-file symbols.dwarf\nptype struct AmbiqApollo4_GPIO',
    expect="""
        (gdb) type = struct AmbiqApollo4_GPIO {
            uint32_t PinConfiguration0[129];"""
)

gdb_test(
    name='Check if macro definition VARIANT0 affects output',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl" -D VARIANT0',
    test='add-symbol-file symbols.dwarf\nptype struct AmbiqApollo4_GPIO',
    expect="""
        (gdb) type = struct AmbiqApollo4_GPIO {
            struct {
                bits FUNCSELregIdx___Function_select_for_GPIO_pin_regIdx : 4;
                bits INPENregIdx___Input_enable_for_GPIO_regIdx : 1;
                bits RDZEROregIdx___Return_0_for_read_data_on_GPIO_regIdx : 1;
                bits IRPTENregIdx___Interrupt_enable_for_GPIO_regIdx : 2;
                bits OUTCFGregIdx___Pin_IO_mode_selection_for_GPIO_pin_regIdx : 2;
                bits bits_22 : 22;
            } PinConfiguration0[129];"""
)

gdb_test(
    name='Check if macro definition VARIANT5 affects output',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl" -D VARIANT5',
    test='add-symbol-file symbols.dwarf\nptype struct AmbiqApollo4_GPIO',
    expect="""
        (gdb) type = struct AmbiqApollo4_GPIO {
            struct {
                bits bits_10 : 10;
                bits DSregIdx___Drive_strength_selection_for_GPIO_regIdx : 2;
                bits SRregIdx___Configure_the_slew_rate : 1;
                bits PULLCFG30___Pullup_Pulldown_configuration_for_GPIO_regIdx : 3;
                bits NCESRCregIdx___IOMSTR_MSPI_N_Chip_Select_regIdx_DISP_control_signals_DE_CSX_and_CS : 6;
                bits NCEPOLregIdx___Polarity_select_for_NCE_for_GPIO_regIdx : 1;
                bits bits_2 : 2;
                bits VDDPWRSWENregIdx___VDD_power_switch_enable : 1;
                bits FIENregIdx___Force_input_enable_active_regardless_of_function_selected : 1;
                bits FOENregIdx___Force_output_enable_active_regardless_of_function_selected : 1;
                bits bits_4 : 4;
            } PinConfiguration0[129];"""
)

gdb_test(
    name='Check if multiple input flags can be used at the same time',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl" -i "$DATA/FT5336.rdl" -q',
    test='add-symbol-file symbols.dwarf\ninfo types',
    expect="""
        (gdb) All defined types:

        File symbols.dwarf.c:
            struct AmbiqApollo4_GPIO;
            struct FT5336;"""
)

gdb_test(
    name='Check if peripheral map creates fallback types',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/stm32f.pmap.json" -q',
    test='add-symbol-file symbols.dwarf\ninfo types',
    expect="""
        (gdb) All defined types:

        File symbols.dwarf.c:
            struct BitBanding;
            struct CortexM;
            struct MappedMemory;
            struct NVIC;
            struct STM32DMA;
            struct STM32F4_EXTI;
            struct STM32F4_FlashController;
            struct STM32F4_I2C;
            struct STM32F4_RCC;
            struct STM32F4_RNG;
            struct STM32F4_RTC;
            struct STM32SPI;
            struct STM32_CRC;
            struct STM32_GPIOPort;
            struct STM32_IndependentWatchdog;
            struct STM32_PWR;
            struct STM32_Timer;
            struct STM32_UART;
            struct STMCAN;
            struct SynopsysEthernetMAC;"""
)

gdb_test(
    name='Check if peripheral map creates global variables',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/STM32F4_I2C.rdl" -i "$DATA/stm32f.pmap.json" -q',
    test='add-symbol-file symbols.dwarf\ninfo variables',
    expect="""
        (gdb) All defined variables:

        File symbols.dwarf.c:
            static struct BitBanding bitbandPeripherals;
            static struct BitBanding bitbandSram;
            static struct STMCAN can1;
            static struct STMCAN can2;
            static struct STM32_CRC crc;
            static struct STM32DMA dma1;
            static struct STM32DMA dma2;
            static struct SynopsysEthernetMAC ethernet;
            static struct STM32F4_EXTI exti;
            static struct MappedMemory flash;
            static struct STM32F4_FlashController flash_controller;
            static struct STM32F4_FlashController flash_controller_1;
            static struct MappedMemory fsmcBank1;
            static struct STM32_GPIOPort gpioPortA;
            static struct STM32_GPIOPort gpioPortB;
            static struct STM32_GPIOPort gpioPortC;
            static struct STM32_GPIOPort gpioPortD;
            static struct STM32_GPIOPort gpioPortE;
            static struct STM32_GPIOPort gpioPortF;
            static struct STM32F4_I2C i2c1;
            static struct STM32F4_I2C i2c2;
            static struct STM32F4_I2C i2c3;
            static struct STM32_IndependentWatchdog iwdg;
            static struct NVIC nvic;
            static struct STM32_PWR pwr;
            static struct STM32F4_RCC rcc;
            static struct STM32F4_RNG rng;
            static struct MappedMemory rom1;
            static struct MappedMemory rom2;
            static struct STM32F4_RTC rtc;
            static struct STM32SPI spi1;
            static struct STM32SPI spi2;
            static struct STM32SPI spi3;
            static struct MappedMemory sram;
            static struct STM32_Timer timer1;
            static struct STM32_Timer timer10;
            static struct STM32_Timer timer11;
            static struct STM32_Timer timer12;
            static struct STM32_Timer timer13;
            static struct STM32_Timer timer14;
            static struct STM32_Timer timer2;
            static struct STM32_Timer timer3;
            static struct STM32_Timer timer4;
            static struct STM32_Timer timer5;
            static struct STM32_Timer timer6;
            static struct STM32_Timer timer7;
            static struct STM32_Timer timer8;
            static struct STM32_Timer timer9;
            static struct STM32_UART uart4;
            static struct STM32_UART uart5;
            static struct STM32_UART usart1;
            static struct STM32_UART usart2;
            static struct STM32_UART usart3;"""
)

gdb_test(
    name='Check if bound peripheral has defined type',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/STM32F4_I2C.rdl" -i "$DATA/stm32f.pmap.json" -q',
    test='add-symbol-file symbols.dwarf\nptype i2c1',
    expect="""
        (gdb) type = struct STM32F4_I2C {
            struct {
                bits PeriEn : 1;
                bits bits_7 : 7;
                bits StartGen : 1;
                bits StopGen : 1;
                bits No_name_1 : 1;
                bits bits_4 : 4;
                bits SWRST : 1;
                bits bits_16 : 16;
            } Control1;
            struct {
                bits Freq : 6;
                bits bits_2 : 2;
                bits No_name_3_ : 1;
                bits No_name_2_ : 1;
                bits No_name_4 : 1;
                bits bits_21 : 21;
            } Control2;
            uint32_t OwnAddress1;
            uint32_t OwnAddress2;
            struct {
                bits No_name_5 : 8;
                bits bits_24 : 24;
            } Data;
            struct {
                bits No_name_10_ : 1;
                bits No_name_9_ : 1;
                bits No_name_8_ : 1;
                bits bits_3 : 3;
                bits No_name_7_ : 1;
                bits No_name_6_ : 1;
                bits bits_2 : 2;
                bits No_name_11 : 1;
                bits bits_21 : 21;
            } Status1;
            struct {
                bits No_name_12_ : 1;
                bits bits_1 : 1;
                bits No_name_13 : 1;
                bits bits_29 : 29;
            } Status2;
            uint32_t ClockControl;
            uint32_t RiseTime;
            uint32_t NoiseFilter;
        }"""
)

gdb_test(
    name='Check if I3C generates valid symbols',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/i3c/src/rdl/registers.rdl" -q',
    test='add-symbol-file symbols.dwarf\nptype struct I3CCSR',
    expect="""
    (gdb) type = struct I3CCSR {
        uint8_t pad_2048[2049];
        struct {
            bits CAP_ID : 8;
            bits CAP_LENGTH : 16;
            bits bits_8 : 8;
        } EXTCAP_HEADER;
        struct {
            bits PENDING_RX_NACK : 1;
            bits HANDOFF_DELAY_NACK : 1;
            bits ACR_FSM_OP_SELECT : 1;
            bits PRIME_ACCEPT_GETACCCR : 1;
            bits HANDOFF_DEEP_SLEEP : 1;
            bits CR_REQUEST_SEND : 1;
            bits bits_2 : 2;
            bits BAST_CCC_IBI_RING : 3;
            bits bits_1 : 1;
            bits TARGET_XACT_ENABLE : 1;
            bits DAA_SETAASA_ENABLE : 1;
            bits DAA_SETDASA_ENABLE : 1;
            bits DAA_ENTDAA_ENABLE : 1;
            bits bits_4 : 4;
            bits RSTACT_DEFBYTE_02 : 1;
            bits bits_9 : 9;
            bits STBY_CR_ENABLE_INIT : 2;
        } STBY_CR_CONTROL;""",
    condition=f'exists("{DATA}/i3c/src/rdl/registers.rdl")'
)

gdb_test(
    name='Check if I3C generates valid symbols with enabled macros',
    setup='java -jar girdl/lib/girdl.jar -i "$DATA/i3c/src/rdl/registers.rdl" -q -D CONTROLLER_SUPPORT -D TARGET_SUPPORT >/dev/null',
    test='add-symbol-file symbols.dwarf\nptype struct I3CCSR',
    expect="""
        (gdb) type = struct I3CCSR {
            uint32_t HCI Version;
            struct {
                bits IBA_INCLUDE : 1;
                bits bits_2 : 2;
                bits AUTOCMD_DATA_RPT : 1;
                bits DATA_BYTE_ORDER_MODE : 1;
                bits bits_1 : 1;
                bits MODE_SELECTOR : 1;
                bits I2C_DEV_PRESENT : 1;
                bits HOT_JOIN_CTRL : 1;
                bits bits_3 : 3;
                bits HALT_ON_CMD_SEQ_TIMEOUT : 1;
                bits bits_16 : 16;
                bits ABORT : 1;
                bits RESUME : 1;
                bits BUS_ENABLE : 1;
            } Control;
            struct {
                bits bits_16 : 16;
                bits DYNAMIC_ADDR : 7;
                bits bits_8 : 8;
                bits DYNAMIC_ADDR_VALID : 1;
            } CONTROLLER_DEVICE_ADDR;
            struct {
                bits bits_2 : 2;
                bits COMBO_COMMAND : 1;
                bits AUTO_COMMAND : 1;
                bits bits_1 : 1;
                bits STANDBY_CR_CAP : 1;
                bits HDR_DDR_EN : 1;
                bits HDR_TS_EN : 1;
                bits bits_2 : 2;
                bits CMD_CCC_DEFBYTE : 1;
                bits IBI_DATA_ABORT_EN : 1;
                bits IBI_CREDIT_COUNT_EN : 1;
                bits SCHEDULED_COMMANDS_EN : 1;
                bits bits_6 : 6;
                bits CMD_SIZE : 2;
                bits bits_6 : 6;
                bits SG_CAPABILITY_CR_EN : 1;
                bits SG_CAPABILITY_IBI_EN : 1;
                bits SG_CAPABILITY_DC_EN : 1;
                bits bits_1 : 1;
            } Capabilities;""",
    condition=f'exists("{DATA}/i3c/src/rdl/registers.rdl")'
)