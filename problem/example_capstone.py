from capstone import *
from binascii import unhexlify

# Machine code x86 32-bit
CODE = unhexlify("414A") # => "\x41\x4A"
BASE_ADDRESS = 0x00400526

def main():
    try:
        # Initialize engine in X86 32-bit mode
        cap = Cs(CS_ARCH_X86, CS_MODE_32)
        for i in cap.disasm(CODE, BASE_ADDRESS):
            print("0x%08x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    except CsError as e:
        print("ERROR: %s" %e)

if __name__ == "__main__":
    main()
