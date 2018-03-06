from unicorn import *
from unicorn.x86_const import *
from binascii import hexlify, unhexlify

X86_CODE32 = unhexlify("414A")
BASE_ADDRESS = 0x0040059d

def main():
    try:
        emu = Uc(UC_ARCH_X86, UC_MODE_32)
        emu.mem_map((BASE_ADDRESS/0x1000)*0x1000, 2 * 1024 * 1024)
        emu.mem_write(BASE_ADDRESS, X86_CODE32)
        emu.reg_write(UC_X86_REG_ECX, 0x9)
        emu.reg_write(UC_X86_REG_EDX, 0x5)
        emu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(X86_CODE32))
        print("Emulation done.")
        print(">>> ECX = 0x%08x" % emu.reg_read(UC_X86_REG_ECX))
        print(">>> EDX = 0x%08x" % emu.reg_read(UC_X86_REG_EDX))
    except UcError as e:
        print("ERROR: %s" % e)

if __name__ == "__main__":
    main()
