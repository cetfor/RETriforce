from keystone import *
from struct import pack
from binascii import hexlify

# Separate assembly instructions by ; or \n
CODE = "INC ECX\n" \
	   "DEC EDX\n"

def main():
    try:
        # Initialize engine in X86 32-bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(CODE)
        machine_code = ""
        for opcode in encoding:
        	machine_code += pack("B", opcode)
        print("Machine Code:\n%s\n" %(hexlify(machine_code)))
    except KsError as e:
        print("ERROR: %s" %e)

if __name__ == "__main__":
    main()
