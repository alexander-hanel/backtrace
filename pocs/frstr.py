"""
Author:
    Alexander Hanel 
Date:
    20140902
Version:
    1  - should be good to go.
Summary:
    Examples of using the backtrace library to rebuild strings

TODO:
    * How to deal with printing wide char strings?
    * What is the size of the frame buffer if GetFrameSize returns something
      smaller than the frame/stack index or the IDA does not recognize the function?

Notes:
    idaapi.o_phrase # Memory Ref [Base Reg + Index Reg]
    o_phrase   =  idaapi.o_phrase    #  Memory Ref [Base Reg + Index Reg]    phrase
    o_displ    =  idaapi.o_displ     #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr

Useful Reads
    http://smokedchicken.org/2012/05/ida-rename-local-from-a-script.html
    http://zairon.wordpress.com/2008/02/15/idc-script-and-stack-frame-variables-length/
"""
import sys, os, logging, copy
from binascii import unhexlify
# Add the parent directory to Python Path
sys.path.append(os.path.realpath(__file__ + "/../../"))
# import the backtrace module
from backtrace import *

class Frame2Buff:
    def __init__(self):
        self.verbose = False
        self.func_start = idc.SelStart()
        # SelEnd() returns the following selected instruction
        self.func_end = SelEnd()
        self.esp = False
        self.ebp = False
        self.comment = True
        self.frame_size = None
        self.bt = None
        self.str_buff = None
        self.comment = True
        self.formatted_buff = ""
        self.format = True

    def run(self, func_addr=None):
        """ run and create Frame2Buff"""
        # check if code is selected or if using the whole function
        if self.func_start == BADADDR or self.func_end == BADADDR:
            if func_addr == None:
                if self.verbose:
                    print "ERROR: No addresses selected or passed"
                return None
        if func_addr:
            self.func_start = idc.GetFunctionAttr(func_addr, FUNCATTR_START)
            self.func_end = idc.GetFunctionAttr(func_addr, FUNCATTR_END)
        if self.func_start == BADADDR:
            if self.verbose:
                print "ERROR: Invalid address"
        self.frame_size = GetFrameSize(self.func_start)
        try:
            self.bt = Backtrace()
            self.bt.verbose = False
        except ImportError:
            print "ERROR: Could not import Backtrace - aborting"
        self.func_end = PrevHead(self.func_end)
        self.populate_buffer()
        if self.format:
            self.format_buff()
        if self.comment:
            self.comment_func()

    def populate_buffer(self):
        curr_addr = self.func_start
        self.str_buff = list('\x00' * self.frame_size)
        while curr_addr <= self.func_end:
            index = None
            idaapi.decode_insn(curr_addr)
            # check if instr is MOV, [esp|ebp + index], variable
            if idaapi.cmd.itype == idaapi.NN_mov and idaapi.cmd.Op1.type == idaapi.o_displ:
                if "bp" in idc.GetOpnd(curr_addr, 0):
                    # ebp will return a negative number
                    index = (~(int(idaapi.cmd.Op1.addr) - 1) & 0xFFFFFFFF)
                    self.ebp = True
                else:
                    index = int(idaapi.cmd.Op1.addr)
                    self.esp = True
                if idaapi.cmd.Op2.type == idaapi.o_reg:
                    # value needs to be traced back
                    self.bt.backtrace(curr_addr, 1)
                    # tainted means the reg was xor reg, reg
                    # odds are being used to init var.
                    if self.bt.tainted != True:
                        last_ref = self.bt.refsLog[-1]
                        idaapi.decode_insn(int(last_ref[0]))
                        data = idaapi.cmd.Op2.value
                    else:
                        # tracked variable has been set to zero by xor reg, reg
                        curr_addr = idc.NextHead(curr_addr)
                        continue
                elif idaapi.cmd.Op2.type != idaapi.o_imm:
                    curr_addr = idc.NextHead(curr_addr)
                    continue
                else:
                    data = idaapi.cmd.Op2.value
                if data:
                    try:
                        hex_values = hex(data)[2:]
                        if hex_values[-1] == "L":
                            hex_values = hex_values[:-1]
                        if len(hex_values) % 2:
                            hex_values = "0" + hex_values
                        temp = unhexlify(hex_values)
                    except:
                        if self.verbose:
                            print "ERROR: Unhexlify Issue at %x %s (not added)" % (curr_addr, idc.GetDisasm(curr_addr))
                        curr_addr = idc.NextHead(curr_addr)
                        continue
                else:
                    curr_addr = idc.NextHead(curr_addr)
                    continue
                # GetFrameSize is not a reliable buffer size
                # If so append to buffer if index is less than
                # 2 * frame size. If more likely an error
                if self.ebp or self.esp:
                    cal_index = index + len(temp)
                    if cal_index > self.frame_size:
                        if cal_index < (self.frame_size * 2):
                            for a in range(cal_index - self.frame_size):
                                self.str_buff.append("\x00")
                                if self.verbose:
                                    print "ERROR: Frame size incorrect, appending"
                if self.ebp:
                    # reverse the buffer
                    temp = temp[::-1]
                    for c, ch in enumerate(temp):
                        try:
                            self.str_buff[index - c] = ch
                        except:
                            if self.verbose:
                                print "ERROR: Frame EBP index invalid: at %x" % (curr_addr)
                if self.esp:
                    for c, ch in enumerate(temp):
                        try:
                            self.str_buff[index + c] = ch
                        except:
                                print "ERROR: Frame ESP index invalid: at %x" % (curr_addr)
            curr_addr = idc.NextHead(curr_addr)

    def format_buff(self):
        self.formatted_buff = ""
        temp_buff = copy.copy(self.str_buff)

        if self.ebp == True:
            temp_buff = temp_buff[::-1]
            temp_buff.pop()

        if self.str_buff:
            for index, ch in enumerate(temp_buff):
                try:
                    if ch == "\x00" and temp_buff[index + 1] != "\x00":
                        self.formatted_buff += " "
                except:
                    pass
                if ch != "\x00":
                    self.formatted_buff += ch

    def comment_func(self):
        idc.MakeComm(self.func_end, self.formatted_buff)

"""
Example:
    Create a buffer of the whole function

x = Frame2Buff()
x.run(here())  # func adddr

"""
x = Frame2Buff()
x.run() # select data
