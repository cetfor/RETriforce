#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keystone import *
from capstone import *
from capstone.x86 import *
from unicorn import *
from unicorn.x86_const import *
from struct import pack
from binascii import hexlify, unhexlify
import argparse

def read_file(fileName):
    f = open(fileName, "r")
    code = f.read()
    f.close()
    return code

def print_registers(emu):
    rax = emu.reg_read(UC_X86_REG_RAX)
    rbx = emu.reg_read(UC_X86_REG_RBX)
    rcx = emu.reg_read(UC_X86_REG_RCX)

    rdx = emu.reg_read(UC_X86_REG_RDX)
    rsi = emu.reg_read(UC_X86_REG_RSI)
    rdi = emu.reg_read(UC_X86_REG_RDI)
    
    rsp = emu.reg_read(UC_X86_REG_RSP)
    rbp = emu.reg_read(UC_X86_REG_RBP)
    rip = emu.reg_read(UC_X86_REG_RIP)

    r8  = emu.reg_read(UC_X86_REG_R8)
    r9  = emu.reg_read(UC_X86_REG_R9)
    r10 = emu.reg_read(UC_X86_REG_R10)
    r11 = emu.reg_read(UC_X86_REG_R11)
    r12 = emu.reg_read(UC_X86_REG_R12)
    r13 = emu.reg_read(UC_X86_REG_R13)
    r14 = emu.reg_read(UC_X86_REG_R14)
    r15 = emu.reg_read(UC_X86_REG_R15)

    print("--------------------------------------------------------------------------------")
    print("/////////////////////////////// REGISTER STATE /////////////////////////////////")
    print("--------------------------------------------------------------------------------")
    print("rax = 0x%016x    rdx = 0x%016x    rsp = 0x%016x" % (rax, rdx, rsp))
    print("rbx = 0x%016x    rsi = 0x%016x    rbp = 0x%016x" % (rbx, rsi, rbp))
    print("rcx = 0x%016x    rdi = 0x%016x    rip = 0x%016x" % (rax, rdi, rip))
    print("r8  = 0x%016x    r9  = 0x%016x    r10 = 0x%016x" % (r8,  r9,  r10))
    print("r11 = 0x%016x    r12 = 0x%016x    r13 = 0x%016x" % (r11, r12, r13))
    print("r14 = 0x%016x    r15 = 0x%016x"                  % (r14, r15))
    print("--------------------------------------------------------------------------------")


def hook_code(emu, address, size, user_data):
    # user_data contains optional data specified by the caller
    # I've included the capstone instance (cap) in a list
    cap = user_data[0]

    # read the opcodes for this instruction
    ocbytes = emu.mem_read(address, size)
    opcodes = hexlify(ocbytes)
    try:
        if cap.detail:
            for inst in cap.disasm(bytes(ocbytes), size):
                print("0x%08x: %s\t%s\t%s" % (address, opcodes.ljust(15), inst.mnemonic, inst.op_str))
                
                # get and print some detailed information about this instruction
                sm_operlen = len(inst.operands)
                print("  Operands: %d" % sm_operlen)

                # if instructions has operands, get more details
                if sm_operlen > 0:
                    c = -1
                    for i in inst.operands:
                        c += 1
                        if i.type == X86_OP_MEM:
                            print("  Type: Memory Operation")

                            # see if the memory operation has a base
                            if i.mem.base != 0:
                                print("  Operand %d mem.base: REG = %s" % (c, inst.reg_name(i.mem.base)))

                            # get memory access type
                            # Note: if you are not on the Capstone "NEXT BRANCH" i.access will fail!
                            # See this: https://github.com/aquynh/capstone/wiki/Next-branch
                            if i.access == CS_AC_READ:
                                print("  Operand %d Access: READ\n" % (c))
                            elif i.access == CS_AC_WRITE:
                                print("  Operand %d Access: WRITE\n" % (c))
                            elif i.access == CS_AC_READ | CS_AC_WRITE:
                                print("  Operand %d Access: READ | WRITE\n" % (c))
                            else:
                                print("  Operand %d Access: UNKNOWN\n" % (c))

                print("")
        else:
            for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cap.disasm_lite(str(ocbytes), address):
                print("0x%08x:\t%s\t%s" % (cs_address, cs_mnemonic, cs_opstr))

    except CsError as e:
        print("CAPSTONE ERROR: %s" % e)


def main():

    BASE_ADDRESS = 0x0000000000400526

    try:
        # Initialize Keystone, Capstone, and Unicorn
        kst = Ks(KS_ARCH_X86, KS_MODE_64)
        cap = Cs(CS_ARCH_X86, CS_MODE_64)
        emu = Uc(UC_ARCH_X86, UC_MODE_64)

        # Emable detailed disassembly if requested by user
        # Allows us to get semantics about each instruction
        if args.detail:
            cap.detail = True

        # Read the assembly code from the user specified file
        ASM_CODE = read_file(args.assembly_file)

        # Assemble our challenge assembly to machine code with Keystone
        try:
            encoding, count = kst.asm(ASM_CODE, BASE_ADDRESS)
            MACHINE_CODE = ""
            for opcode in encoding:
                MACHINE_CODE += pack("B", opcode)
        except KsError as e:
            # ruh-roh, we cannot recover from an assembly error, bail out
            print("KEYSTONE ERROR: %s" % e)
            exit()

        # Hook each instruction so we can print them with Capstone
        emu.hook_add(UC_HOOK_CODE, hook_code, [cap])

        # Create 2MB of memory at the closest page boundary for the code
        emu.mem_map((BASE_ADDRESS/0x1000)*0x1000, 2 * 1024 * 1024)

        # Write our challenge code to the base address
        emu.mem_write(BASE_ADDRESS, MACHINE_CODE)

        # create stack space for the code to use
        # location is completely arbitrary, size depends on code being emulated
        # do not "collide" with your executable code (MACHINE_CODE) space!
        STACK_START = 0x0000000000200000
        STACK_SIZE  = 0x0000000000010000
        emu.mem_map(STACK_START - STACK_SIZE, STACK_SIZE)

        # set stack pointer and base pointer to the location of our stack
        emu.reg_write(UC_X86_REG_RSP, STACK_START)
        emu.reg_write(UC_X86_REG_RBP, STACK_START)

        # setting RIP is not required, we do it so the regitser print isn't misleading
        # emu_start sets RIP for us
        emu.reg_write(UC_X86_REG_RIP, BASE_ADDRESS)
        
        # Print the starting register state
        print_registers(emu)

        # Run emulation from the start of code to the end
        # Registers and memory initialize to ZERO (0x0000000000000000)
        emu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(MACHINE_CODE))
        
        # Print the flag. We know RAX and RDI contain a pointer to the flag on the stack
        rax = emu.reg_read(UC_X86_REG_RAX)

        # read 40 bytes from the flag pointer (size is arbitrarily chosen, flag ends up being 21 bytes)
        flag = emu.mem_read(rax, 40)

        # print the final register state
        print_registers(emu)

        # print the flag
        print("Flag: %s" % flag)

    except UcError as e:
        print("UNICORN ERROR: %s" % e)
        

if __name__ == "__main__":
    # argument parsing
    parser = argparse.ArgumentParser(description="RETriforce: Keystone, Capstone, Unicorn Example")

    # required arguments
    parser.add_argument('assembly_file', action='store', help='x86_64 assembly file')

    # optional arguments
    parser.add_argument('--detail', action='store_true', help='print semantic information about instructions')
    args = parser.parse_args()
    main()
