#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export DATA="$(pwd)/src/test/resources"

# Check if string [stdin] contains another string [$1] as substring.
# We can't just use grep here as it works line-by-line,
# and can't match multiline string in -F mode, one way
# we COULD achieve the same with grep would be to convert
# the string to perl regular expression (-P) first
function strstr() {
python3 -c "$(cat <<-PY
import sys
needle = sys.argv[1]
haystack = sys.stdin.read().replace('\t', "        ")

if needle in haystack:
  exit(0)

print(f'\033[1;31mSubstring \033[0m"{needle}"\033[1;31m not found in input \033[0m"{haystack}"')
exit(1)
PY
)" "$1"
}

function test() {
  echo -e "\n\e[1mTEST: \e[36m$1\e[0m"
}

function passed() {
  echo -e "\e[1;32m      PASSED\e[0m"
}

function skipped() {
  echo -e "\e[1;33m      SKIPPED\e[0m"
}

function cleanup() {
  rm -rf ./standalone
}

cleanup
mkdir standalone

cp dist/girdl.zip standalone/girdl.zip
pushd standalone
unzip -q girdl.zip
set +x
time (


test "Check if standalone mode launches"
java -jar girdl/lib/girdl.jar --help | strstr "Print this help page"
passed


test "Check if peripheral types are being exported"
java -jar girdl/lib/girdl.jar -i "$DATA/FT5336.rdl" -q
echo -e "add-symbol-file symbols.dwarf\ninfo types" | gdb | strstr "$(cat <<-EXPCT
(gdb) All defined types:

File peripherals:
        struct FT5336;
        uint8_t
(gdb)
EXPCT
)"
passed


test "Check if registers are correctly added to the peripheral"
java -jar girdl/lib/girdl.jar -i "$DATA/FT5336.rdl" -q
echo -e "add-symbol-file symbols.dwarf\nptype struct FT5336" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct FT5336 {
    uint8_t TouchXHigh;
    uint8_t TouchXLow;
    uint8_t TouchYHigh;
    uint8_t TouchYLow;
    uint8_t TouchWeight;
    uint8_t TouchMisc;
}
(gdb)
EXPCT
)"
passed


test "Check if output can be changed"
java -jar girdl/lib/girdl.jar -i "$DATA/FT5336.rdl" -q -o "output.elf"
echo -e "add-symbol-file output.elf\ninfo types" | gdb | strstr "$(cat <<-EXPCT
(gdb) All defined types:

File peripherals:
        struct FT5336;
        uint8_t
(gdb)
EXPCT
)"
passed


test "Check if SVD imports all peripheral types"
java -jar girdl/lib/girdl.jar -i "$DATA/STM32WL33.svd" -q > /dev/null
echo -e "add-symbol-file symbols.dwarf\ninfo types" | gdb | strstr "$(cat <<-EXPCT
(gdb) All defined types:

File peripherals:
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
        struct USART;
EXPCT
)"
passed


test "Check if SVD imports binds peripherals as variables"
java -jar girdl/lib/girdl.jar -i "$DATA/STM32WL33.svd" -q > /dev/null
echo -e "add-symbol-file symbols.dwarf\ninfo variables" | gdb | strstr "$(cat <<-EXPCT
(gdb) All defined variables:

File peripherals:
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
        static struct USART USART;
EXPCT
)"
passed


test "Check if SVD imports registers and fields from peripherals"
java -jar girdl/lib/girdl.jar -i "$DATA/STM32WL33.svd" -q > /dev/null
echo -e "add-symbol-file symbols.dwarf\nptype struct RCC" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct RCC {
    struct {
        uint64_t bits_2 : 2;
        uint64_t LSION : 1;
        uint64_t LSIRDY : 1;
        uint64_t LSEON : 1;
        uint64_t LSERDY : 1;
        uint64_t LSEBYP : 1;
        uint64_t LOCKDET_NSTOP : 3;
        uint64_t HSIRDY : 1;
        uint64_t bits_1 : 1;
        uint64_t HSEPLLBUFON : 1;
        uint64_t HSIPLLON : 1;
        uint64_t HSIPLLRDY : 1;
        uint64_t FMRAT : 1;
        uint64_t HSEON : 1;
        uint64_t HSERDY : 1;
        uint64_t bits_14 : 14;
    } CR;
    struct {
        uint64_t LSITRIMEN : 1;
        uint64_t LSITRIMOK : 1;
        uint64_t LSIBW : 4;
        uint64_t bits_10 : 10;
        uint64_t HSITRIMOFFSET : 3;
        uint64_t bits_5 : 5;
        uint64_t HSITRIM : 6;
        uint64_t bits_2 : 2;
    } ICSCR;
    struct {
        uint64_t bits_1 : 1;
        uint64_t HSESEL : 1;
        uint64_t STOPHSI : 1;
        uint64_t HSESEL_STATUS : 1;
        uint64_t bits_1 : 1;
        uint64_t CLKSYSDIV : 3;
        uint64_t CLKSYSDIV_STATUS : 3;
        uint64_t bits_1 : 1;
        uint64_t SMPSDIV : 1;
        uint64_t LPUCLKSEL : 1;
        uint64_t bits_1 : 1;
        uint64_t CLKSLOWSEL : 2;
        uint64_t IOBOOSTEN : 1;
        uint64_t bits_1 : 1;
        uint64_t LCOEN : 1;
        uint64_t bits_2 : 2;
        uint64_t SPI3I2SCLKSEL : 2;
        uint64_t LCOSEL : 2;
        uint64_t MCOSEL : 3;
        uint64_t CCOPRE : 3;
    } CFGR;
EXPCT
)"
passed


test "Check if register fields are being exported"
java -jar girdl/lib/girdl.jar -i "$DATA/SAMD21_Timer.rdl" -q
echo -e "add-symbol-file symbols.dwarf\nptype struct SAMD21_Timer" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct SAMD21_Timer {
    struct {
        uint64_t SWRST : 1;
        uint64_t ENABLE : 1;
        uint64_t MODE : 2;
        uint64_t bits_1 : 1;
        uint64_t WAVEGEN : 2;
        uint64_t bits_1 : 1;
    } ControlA0;
    struct {
        uint64_t PRESCALER : 3;
        uint64_t RUNSTDBY : 1;
        uint64_t PRESCSYNC : 2;
        uint64_t bits_2 : 2;
    } ControlA1;
    uint8_t ReadRequest0;
    uint8_t ReadRequest1;
    struct {
        uint64_t DIR : 1;
        uint64_t bits_1 : 1;
        uint64_t ONESHOT : 1;
        uint64_t bits_3 : 3;
        uint64_t CMD : 2;
    } ControlBClear;
    struct {
        uint64_t DIR : 1;
        uint64_t bits_1 : 1;
        uint64_t ONESHOT : 1;
        uint64_t bits_3 : 3;
        uint64_t CMD : 2;
    } ControlBSet;
    uint8_t ControlC;
    uint8_t Reserved0;
    uint8_t DebugControl;
    uint8_t Reserved1;
    uint16_t EventControl;
    struct {
        uint64_t OVF : 1;
        uint64_t ERR : 1;
        uint64_t bits_1 : 1;
        uint64_t SYNCRDY : 1;
        uint64_t MC0 : 1;
        uint64_t MC1 : 1;
        uint64_t bits_2 : 2;
    } InterruptEnableClear;
    struct {
        uint64_t OVF : 1;
        uint64_t ERR : 1;
        uint64_t bits_1 : 1;
        uint64_t SYNCRDY : 1;
        uint64_t MC0 : 1;
        uint64_t MC1 : 1;
        uint64_t bits_2 : 2;
    } InterruptEnableSet;
    struct {
        uint64_t OVF : 1;
        uint64_t ERR : 1;
        uint64_t bits_1 : 1;
        uint64_t SYNCRDY : 1;
        uint64_t MC0 : 1;
        uint64_t MC1 : 1;
        uint64_t bits_2 : 2;
    } InterruptFlags;
    struct {
        uint64_t bits_3 : 3;
        uint64_t STOP : 1;
        uint64_t bits_3 : 3;
        uint64_t SYNCBUSY : 1;
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
(gdb)
EXPCT
)"
passed


test "Check if no default macro is provided"
java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl"
echo -e "add-symbol-file symbols.dwarf\nptype struct AmbiqApollo4_GPIO" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct AmbiqApollo4_GPIO {
    uint32_t PinConfiguration0[129];
EXPCT
)"
passed


test "Check if macro definition VARIANT0 affects output"
java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl" -D VARIANT0
echo -e "add-symbol-file symbols.dwarf\nptype struct AmbiqApollo4_GPIO" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct AmbiqApollo4_GPIO {
    struct {
        uint64_t FUNCSELregIdx___Function_select_for_GPIO_pin_regIdx : 4;
        uint64_t INPENregIdx___Input_enable_for_GPIO_regIdx : 1;
        uint64_t RDZEROregIdx___Return_0_for_read_data_on_GPIO_regIdx : 1;
        uint64_t IRPTENregIdx___Interrupt_enable_for_GPIO_regIdx : 2;
        uint64_t OUTCFGregIdx___Pin_IO_mode_selection_for_GPIO_pin_regIdx : 2;
        uint64_t bits_22 : 22;
    } PinConfiguration0[129];
EXPCT
)"
passed


test "Check if macro definition VARIANT5 affects output"
java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl" -D VARIANT5
echo -e "add-symbol-file symbols.dwarf\nptype struct AmbiqApollo4_GPIO" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct AmbiqApollo4_GPIO {
    struct {
        uint64_t bits_10 : 10;
        uint64_t DSregIdx___Drive_strength_selection_for_GPIO_regIdx : 2;
        uint64_t SRregIdx___Configure_the_slew_rate : 1;
        uint64_t PULLCFG30___Pullup_Pulldown_configuration_for_GPIO_regIdx : 3;
        uint64_t NCESRCregIdx___IOMSTR_MSPI_N_Chip_Select_regIdx_DISP_control_signals_DE_CSX_and_CS : 6;
        uint64_t NCEPOLregIdx___Polarity_select_for_NCE_for_GPIO_regIdx : 1;
        uint64_t bits_2 : 2;
        uint64_t VDDPWRSWENregIdx___VDD_power_switch_enable : 1;
        uint64_t FIENregIdx___Force_input_enable_active_regardless_of_function_selected : 1;
        uint64_t FOENregIdx___Force_output_enable_active_regardless_of_function_selected : 1;
        uint64_t bits_4 : 4;
    } PinConfiguration0[129];
EXPCT
)"
passed


test "Check if multiple input flags can be used at the same time"
java -jar girdl/lib/girdl.jar -i "$DATA/AmbiqApollo4_GPIO.rdl" -i "$DATA/FT5336.rdl" -q
echo -e "add-symbol-file symbols.dwarf\ninfo types" | gdb | strstr "$(cat <<-EXPCT
(gdb) All defined types:

File peripherals:
        struct AmbiqApollo4_GPIO;
        struct FT5336;
EXPCT
)"
passed


test "Check if peripheral map creates fallback types"
java -jar girdl/lib/girdl.jar -i "$DATA/stm32f.pmap.json" -q
echo -e "add-symbol-file symbols.dwarf\ninfo types" | gdb | strstr "$(cat <<-EXPCT
(gdb) All defined types:

File peripherals:
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
        struct SynopsysEthernetMAC;
EXPCT
)"
passed


test "Check if peripheral map creates global variables"
java -jar girdl/lib/girdl.jar -i "$DATA/STM32F4_I2C.rdl" -i "$DATA/stm32f.pmap.json" -q
echo -e "add-symbol-file symbols.dwarf\ninfo variables" | gdb | strstr "$(cat <<-EXPCT
(gdb) All defined variables:

File peripherals:
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
        static struct STM32_UART usart3;
EXPCT
)"
passed


test "Check if bound peripheral has defined type"
java -jar girdl/lib/girdl.jar -i "$DATA/STM32F4_I2C.rdl" -i "$DATA/stm32f.pmap.json" -q
echo -e "add-symbol-file symbols.dwarf\nptype i2c1" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct STM32F4_I2C {
    struct {
        uint64_t PeriEn : 1;
        uint64_t bits_7 : 7;
        uint64_t StartGen : 1;
        uint64_t StopGen : 1;
        uint64_t No_name_1 : 1;
        uint64_t bits_4 : 4;
        uint64_t SWRST : 1;
        uint64_t bits_16 : 16;
    } Control1;
    struct {
        uint64_t Freq : 6;
        uint64_t bits_2 : 2;
        uint64_t No_name_3_ : 1;
        uint64_t No_name_2_ : 1;
        uint64_t No_name_4 : 1;
        uint64_t bits_21 : 21;
    } Control2;
    uint32_t OwnAddress1;
    uint32_t OwnAddress2;
    struct {
        uint64_t No_name_5 : 8;
        uint64_t bits_24 : 24;
    } Data;
    struct {
        uint64_t No_name_10_ : 1;
        uint64_t No_name_9_ : 1;
        uint64_t No_name_8_ : 1;
        uint64_t bits_3 : 3;
        uint64_t No_name_7_ : 1;
        uint64_t No_name_6_ : 1;
        uint64_t bits_2 : 2;
        uint64_t No_name_11 : 1;
        uint64_t bits_21 : 21;
    } Status1;
    struct {
        uint64_t No_name_12_ : 1;
        uint64_t bits_1 : 1;
        uint64_t No_name_13 : 1;
        uint64_t bits_29 : 29;
    } Status2;
    uint32_t ClockControl;
    uint32_t RiseTime;
    uint32_t NoiseFilter;
}
EXPCT
)"
passed


test "Check if I3C generates valid symbols"
if [[ -e "$DATA/i3c/src/rdl/registers.rdl" ]]; then
java -jar girdl/lib/girdl.jar -i "$DATA/i3c/src/rdl/registers.rdl" -q
echo -e "add-symbol-file symbols.dwarf\nptype struct I3CCSR" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct I3CCSR {
    uint8_t pad_2048[2049];
    struct {
        uint64_t CAP_ID : 8;
        uint64_t CAP_LENGTH : 16;
        uint64_t bits_8 : 8;
    } EXTCAP_HEADER;
    struct {
        uint64_t PENDING_RX_NACK : 1;
        uint64_t HANDOFF_DELAY_NACK : 1;
        uint64_t ACR_FSM_OP_SELECT : 1;
        uint64_t PRIME_ACCEPT_GETACCCR : 1;
        uint64_t HANDOFF_DEEP_SLEEP : 1;
        uint64_t CR_REQUEST_SEND : 1;
        uint64_t bits_2 : 2;
        uint64_t BAST_CCC_IBI_RING : 3;
        uint64_t bits_1 : 1;
        uint64_t TARGET_XACT_ENABLE : 1;
        uint64_t DAA_SETAASA_ENABLE : 1;
        uint64_t DAA_SETDASA_ENABLE : 1;
        uint64_t DAA_ENTDAA_ENABLE : 1;
        uint64_t bits_4 : 4;
        uint64_t RSTACT_DEFBYTE_02 : 1;
        uint64_t bits_9 : 9;
        uint64_t STBY_CR_ENABLE_INIT : 2;
    } STBY_CR_CONTROL;
EXPCT
)"
passed
else
  skipped
fi


test "Check if I3C generates valid symbols with enabled macros"
if [[ -e "$DATA/i3c/src/rdl/registers.rdl" ]]; then
java -jar girdl/lib/girdl.jar -i "$DATA/i3c/src/rdl/registers.rdl" -q -D CONTROLLER_SUPPORT -D TARGET_SUPPORT >/dev/null
echo -e "add-symbol-file symbols.dwarf\nptype struct I3CCSR" | gdb | strstr "$(cat <<-EXPCT
(gdb) type = struct I3CCSR {
    uint32_t HCI Version;
    struct {
        uint64_t IBA_INCLUDE : 1;
        uint64_t bits_2 : 2;
        uint64_t AUTOCMD_DATA_RPT : 1;
        uint64_t DATA_BYTE_ORDER_MODE : 1;
        uint64_t bits_1 : 1;
        uint64_t MODE_SELECTOR : 1;
        uint64_t I2C_DEV_PRESENT : 1;
        uint64_t HOT_JOIN_CTRL : 1;
        uint64_t bits_3 : 3;
        uint64_t HALT_ON_CMD_SEQ_TIMEOUT : 1;
        uint64_t bits_16 : 16;
        uint64_t ABORT : 1;
        uint64_t RESUME : 1;
        uint64_t BUS_ENABLE : 1;
    } Control;
    struct {
        uint64_t bits_16 : 16;
        uint64_t DYNAMIC_ADDR : 7;
        uint64_t bits_8 : 8;
        uint64_t DYNAMIC_ADDR_VALID : 1;
    } CONTROLLER_DEVICE_ADDR;
    struct {
        uint64_t bits_2 : 2;
        uint64_t COMBO_COMMAND : 1;
        uint64_t AUTO_COMMAND : 1;
        uint64_t bits_1 : 1;
        uint64_t STANDBY_CR_CAP : 1;
        uint64_t HDR_DDR_EN : 1;
        uint64_t HDR_TS_EN : 1;
        uint64_t bits_2 : 2;
        uint64_t CMD_CCC_DEFBYTE : 1;
        uint64_t IBI_DATA_ABORT_EN : 1;
        uint64_t IBI_CREDIT_COUNT_EN : 1;
        uint64_t SCHEDULED_COMMANDS_EN : 1;
        uint64_t bits_6 : 6;
        uint64_t CMD_SIZE : 2;
        uint64_t bits_6 : 6;
        uint64_t SG_CAPABILITY_CR_EN : 1;
        uint64_t SG_CAPABILITY_IBI_EN : 1;
        uint64_t SG_CAPABILITY_DC_EN : 1;
        uint64_t bits_1 : 1;
    } Capabilities;
EXPCT
)"
passed
else
  skipped
fi


);
echo
set -x
popd
cleanup
