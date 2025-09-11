/*
 * Copyright 2025 Antmicro
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.antmicro.girdl.data.elf.enums;

public class ElfMachine {

	public static final int NONE = 0; /// No machine
	public static final int M32 = 1; /// AT&T WE 32100
	public static final int SPARC = 2; /// SUN SPARC
	public static final int I386 = 3; /// Intel 80386
	public static final int M68K = 4; /// Motorola m68k family
	public static final int M88K = 5; /// Motorola m88k family
	public static final int IAMCU = 6; /// Intel MCU
	public static final int I860 = 7; /// Intel 80860
	public static final int MIPS = 8; /// MIPS R3000 big-endian
	public static final int S370 = 9; /// IBM System/370
	public static final int MIPS_RS3_LE = 10; /// MIPS R3000 little-endian
	public static final int PARISC = 15; /// HPPA
	public static final int VPP500 = 17; /// Fujitsu VPP500
	public static final int SPARC32PLUS = 18; /// Sun's "v8plus"
	public static final int I960 = 19; /// Intel 80960
	public static final int PPC = 20; /// PowerPC
	public static final int PPC64 = 21; /// PowerPC 64-bit
	public static final int S390 = 22; /// IBM S390
	public static final int SPU = 23; /// IBM SPU/SPC
	public static final int V800 = 36; /// NEC V800 series
	public static final int FR20 = 37; /// Fujitsu FR20
	public static final int RH32 = 38; /// TRW RH-32
	public static final int RCE = 39; /// Motorola RCE
	public static final int ARM = 40; /// ARM
	public static final int FAKE_ALPHA = 41; /// Digital Alpha
	public static final int SH = 42; /// Hitachi SH
	public static final int SPARCV9 = 43; /// SPARC v9 64-bit
	public static final int TRICORE = 44; /// Siemens Tricore
	public static final int ARC = 45; /// Argonaut RISC Core
	public static final int H8_300 = 46; /// Hitachi H8/300
	public static final int H8_300H = 47; /// Hitachi H8/300H
	public static final int H8S = 48; /// Hitachi H8S
	public static final int H8_500 = 49; /// Hitachi H8/500
	public static final int IA_64 = 50; /// Intel Merced
	public static final int MIPS_X = 51; /// Stanford MIPS-X
	public static final int COLDFIRE = 52; /// Motorola Coldfire
	public static final int M68HC12 = 53; /// Motorola M68HC12
	public static final int MMA = 54; /// Fujitsu MMA Multimedia Accelerator
	public static final int PCP = 55; /// Siemens PCP
	public static final int NCPU = 56; /// Sony nCPU embeeded RISC
	public static final int NDR1 = 57; /// Denso NDR1 microprocessor
	public static final int STARCORE = 58; /// Motorola Start*Core processor
	public static final int ME16 = 59; /// Toyota ME16 processor
	public static final int ST100 = 60; /// STMicroelectronic ST100 processor
	public static final int TINYJ = 61; /// Advanced Logic Corp. Tinyj emb.fam
	public static final int X86_64 = 62; /// AMD x86-64 architecture
	public static final int PDSP = 63; /// Sony DSP Processor
	public static final int PDP10 = 64; /// Digital PDP-10
	public static final int PDP11 = 65; /// Digital PDP-11
	public static final int FX66 = 66; /// Siemens FX66 microcontroller
	public static final int ST9PLUS = 67; /// STMicroelectronics ST9+ 8/16 mc
	public static final int ST7 = 68; /// STmicroelectronics ST7 8 bit mc
	public static final int M68HC16 = 69; /// Motorola MC68HC16 microcontroller
	public static final int M68HC11 = 70; /// Motorola MC68HC11 microcontroller
	public static final int M68HC08 = 71; /// Motorola MC68HC08 microcontroller
	public static final int M68HC05 = 72; /// Motorola MC68HC05 microcontroller
	public static final int SVX = 73; /// Silicon Graphics SVx
	public static final int ST19 = 74; /// STMicroelectronics ST19 8 bit mc
	public static final int VAX = 75; /// Digital VAX
	public static final int CRIS = 76; /// Axis Communications 32-bit emb.proc
	public static final int JAVELIN = 77; /// Infineon Technologies 32-bit emb.proc
	public static final int FIREPATH = 78; /// Element 14 64-bit DSP Processor
	public static final int ZSP = 79; /// LSI Logic 16-bit DSP Processor
	public static final int MMIX = 80; /// Donald Knuth's educational 64-bit proc
	public static final int HUANY = 81; /// Harvard University machine-independent object files
	public static final int PRISM = 82; /// SiTera Prism
	public static final int AVR = 83; /// Atmel AVR 8-bit microcontroller
	public static final int FR30 = 84; /// Fujitsu FR30
	public static final int D10V = 85; /// Mitsubishi D10V
	public static final int D30V = 86; /// Mitsubishi D30V
	public static final int V850 = 87; /// NEC v850
	public static final int M32R = 88; /// Mitsubishi M32R
	public static final int MN10300 = 89; /// Matsushita MN10300
	public static final int MN10200 = 90; /// Matsushita MN10200
	public static final int PJ = 91; /// picoJava
	public static final int OPENRISC = 92; /// OpenRISC 32-bit embedded processor
	public static final int ARC_COMPACT = 93; /// ARC International ARCompact
	public static final int XTENSA = 94; /// Tensilica Xtensa Architecture
	public static final int VIDEOCORE = 95; /// Alphamosaic VideoCore
	public static final int TMM_GPP = 96; /// Thompson Multimedia General Purpose Proc
	public static final int NS32K = 97; /// National Semi. 32000
	public static final int TPC = 98; /// Tenor Network TPC
	public static final int SNP1K = 99; /// Trebia SNP 1000
	public static final int ST200 = 100; /// STMicroelectronics ST200
	public static final int IP2K = 101; /// Ubicom IP2xxx
	public static final int MAX	 = 102; /// MAX processor
	public static final int CR = 103; /// National Semi. CompactRISC
	public static final int F2MC16 = 104; /// Fujitsu F2MC16
	public static final int MSP430 = 105; /// Texas Instruments msp430
	public static final int BLACKFIN = 106; /// Analog Devices Blackfin DSP
	public static final int SE_C33 = 107; /// Seiko Epson S1C33 family
	public static final int SEP = 108; /// Sharp embedded microprocessor
	public static final int ARCA = 109; /// Arca RISC
	public static final int UNICORE = 110; /// PKU-Unity & MPRC Peking Uni. mc series
	public static final int EXCESS = 111; /// eXcess configurable cpu
	public static final int DXP = 112; /// Icera Semi. Deep Execution Processor
	public static final int ALTERA_NIOS2 = 113; /// Altera Nios II
	public static final int CRX	 = 114; /// National Semi. CompactRISC CRX
	public static final int XGATE = 115; /// Motorola XGATE
	public static final int C166 = 116; /// Infineon C16x/XC16x
	public static final int M16C = 117; /// Renesas M16C
	public static final int DSPIC30F = 118; /// Microchip Technology dsPIC30F
	public static final int CE = 119; /// Freescale Communication Engine RISC
	public static final int M32C = 120; /// Renesas M32C
	public static final int TSK3000 = 131; /// Altium TSK3000
	public static final int RS08 = 132; /// Freescale RS08
	public static final int SHARC = 133; /// Analog Devices SHARC family
	public static final int ECOG2 = 134; /// Cyan Technology eCOG2
	public static final int SCORE7 = 135; /// Sunplus S+core7 RISC
	public static final int DSP24 = 136; /// New Japan Radio (NJR) 24-bit DSP
	public static final int VIDEOCORE3 = 137; /// Broadcom VideoCore III
	public static final int LATTICEMICO32 = 138; /// RISC for Lattice FPGA
	public static final int SE_C17 = 139; /// Seiko Epson C17
	public static final int TI_C6000 = 140; /// Texas Instruments TMS320C6000 DSP
	public static final int TI_C2000 = 141; /// Texas Instruments TMS320C2000 DSP
	public static final int TI_C5500 = 142; /// Texas Instruments TMS320C55x DSP
	public static final int TI_ARP32 = 143; /// Texas Instruments App. Specific RISC
	public static final int TI_PRU = 144; /// Texas Instruments Prog. Realtime Unit
	public static final int MMDSP_PLUS = 160; /// STMicroelectronics 64bit VLIW DSP
	public static final int CYPRESS_M8C = 161; /// Cypress M8C
	public static final int R32C = 162; /// Renesas R32C
	public static final int TRIMEDIA = 163; /// NXP Semi. TriMedia
	public static final int QDSP6 = 164; /// QUALCOMM DSP6
	public static final int I8051 = 165; /// Intel 8051 and variants
	public static final int STXP7X = 166; /// STMicroelectronics STxP7x
	public static final int NDS32 = 167; /// Andes Tech. compact code emb. RISC
	public static final int ECOG1X = 168; /// Cyan Technology eCOG1X
	public static final int MAXQ30 = 169; /// Dallas Semi. MAXQ30 mc
	public static final int XIMO16 = 170; /// New Japan Radio (NJR) 16-bit DSP
	public static final int MANIK = 171; /// M2000 Reconfigurable RISC
	public static final int CRAYNV2 = 172; /// Cray NV2 vector architecture
	public static final int RX = 173; /// Renesas RX
	public static final int METAG = 174; /// Imagination Tech. META
	public static final int MCST_ELBRUS = 175; /// MCST Elbrus
	public static final int ECOG16 = 176; /// Cyan Technology eCOG16
	public static final int CR16 = 177; /// National Semi. CompactRISC CR16
	public static final int ETPU = 178; /// Freescale Extended Time Processing Unit
	public static final int SLE9X = 179; /// Infineon Tech. SLE9X
	public static final int L10M = 180; /// Intel L10M
	public static final int K10M = 181; /// Intel K10M
	public static final int AARCH64 = 183; /// ARM AARCH64
	public static final int AVR32 = 185; /// Amtel 32-bit microprocessor
	public static final int STM8 = 186; /// STMicroelectronics STM8
	public static final int TILE64 = 187; /// Tilera TILE64
	public static final int TILEPRO = 188; /// Tilera TILEPro
	public static final int MICROBLAZE = 189; /// Xilinx MicroBlaze
	public static final int CUDA = 190; /// NVIDIA CUDA
	public static final int TILEGX = 191; /// Tilera TILE-Gx
	public static final int CLOUDSHIELD = 192; /// CloudShield
	public static final int COREA_1ST = 193; /// KIPO-KAIST Core-A 1st gen.
	public static final int COREA_2ND = 194; /// KIPO-KAIST Core-A 2nd gen.
	public static final int ARCV2 = 195; /// Synopsys ARCv2 ISA.
	public static final int OPEN8 = 196; /// Open8 RISC
	public static final int RL78 = 197; /// Renesas RL78
	public static final int VIDEOCORE5 = 198; /// Broadcom VideoCore V
	public static final int R78KOR = 199; /// Renesas 78KOR
	public static final int F56800EX = 200; /// Freescale 56800EX DSC
	public static final int BA1 = 201; /// Beyond BA1
	public static final int BA2 = 202; /// Beyond BA2
	public static final int XCORE = 203; /// XMOS xCORE
	public static final int MCHP_PIC = 204; /// Microchip 8-bit PIC(r)
	public static final int INTELGT = 205; /// Intel Graphics Technology
	public static final int KM32 = 210; /// KM211 KM32
	public static final int KMX32 = 211; /// KM211 KMX32
	public static final int EMX16 = 212; /// KM211 KMX16
	public static final int EMX8 = 213; /// KM211 KMX8
	public static final int KVARC = 214; /// KM211 KVARC
	public static final int CDP = 215; /// Paneve CDP
	public static final int COGE = 216; /// Cognitive Smart Memory Processor
	public static final int COOL = 217; /// Bluechip CoolEngine
	public static final int NORC = 218; /// Nanoradio Optimized RISC
	public static final int CSR_KALIMBA = 219; /// CSR Kalimba
	public static final int Z80 = 220; /// Zilog Z80
	public static final int VISIUM = 221; /// Controls and Data Services VISIUMcore
	public static final int FT32 = 222; /// FTDI Chip FT32
	public static final int MOXIE = 223; /// Moxie processor
	public static final int AMDGPU = 224; /// AMD GPU
	public static final int RISCV = 243; /// RISC-V
	public static final int BPF = 247; /// Linux BPF -- in-kernel virtual machine
	public static final int CSKY = 252; /// C-SKY

}
