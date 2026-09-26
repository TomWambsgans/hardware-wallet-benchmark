/* Flat layout for running the crypto code under Unicorn (tools/emu/run.py). */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x00010000, LENGTH = 256K
  SRAM  (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS
{
  .text : { *(.text*) *(.rodata*) } > FLASH
  .data : { _sb = .; *(.data*) *(.bss*) *(COMMON) } > SRAM
}
