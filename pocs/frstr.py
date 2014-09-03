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
import sys, os, logging
from binascii import unhexlify
# Add the parent directory to Python Path
sys.path.append(os.path.realpath(__file__ + "/../../"))
# import the backtrace module
from backtrace import *

class Frame2Buff:
    def __init__(self):
        self.verbose = True
        self.func_start = idc.SelStart()
        # SelEnd() returns the following selected instruction
        self.func_end = SelEnd()
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
        logging.debug('Calling self.populate_buffer()')
        self.func_end = PrevHead(self.func_end)
        self.populate_buffer()
        if self.format:
            self.format_buff()
        if self.comment:
            self.comment_func()

    def populate_buffer(self):
        curr_addr = self.func_start
        self.ebp = False
        self.esp = False
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
                # try/except added because GetFrameSize is not always a good way to 
                # estimate the frame buffer size
                if self.ebp:
                    # reverse the buffer
                    temp = temp[::-1]
                    for c, ch in enumerate(temp):
                        try:
                            self.str_buff[index - c ] = ch
                        except:
                            if self.verbose:
                                print "ERROR: Frame index invalid: at %x" % (curr_addr)
                if self.esp:
                    for c, ch in enumerate(temp):
                        try:
                            self.str_buff[index + c] = ch
                        except:
                             if self.verbose:
                                    print "ERROR: Frame index invalid: at %x" % (curr_addr)
            curr_addr = idc.NextHead(curr_addr)

    def format_buff(self):
        self.formatted_buff = ""
        if self.ebp == True:
            self.str_buff = self.str_buff[::-1]
            self.str_buff.pop()

        if self.str_buff:
            for index, ch in enumerate(self.str_buff):
                try:
                    if ch == "\x00" and self.str_buff[index + 1] != "\x00":
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
