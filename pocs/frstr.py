"""
Author:
    Alexander Hanel
Date:
    20140831
Version:
    .2   - should be good to go.
Summary:
    Examples of using the backtrace library to rebuild strings

TODO:
    * Add better error handling
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
#from math import log
sys.path.append(os.path.realpath(__file__ + "/../../"))
from backtrace import *

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

def use_frame_size(start):
    return idc.GetFrameSize(start)

def get_strings(start, end, size):
    b = Backtrace()
    esp = False
    ebp = False
    b.verbose = False
    str_buff = list('\x00' * size)
    curr_addr = start
    while curr_addr <= end:
        idaapi.decode_insn(curr_addr)
        if idaapi.cmd.itype == idaapi.NN_mov and \
           idaapi.cmd.Op1.type == idaapi.o_displ:
            # get the frame pointer address, used as index
            # [?] Can the base pointer or stack pointer be found without
            # [?] string parsing?
            if "bp" in idc.GetOpnd(curr_addr,0):
                # ebp will return a negative number
                index = (~(int(idaapi.cmd.Op1.addr) - 1) & 0xFFFFFFFF)
                ebp = True
            else:
                index = int(idaapi.cmd.Op1.addr)
                esp = True
            if idaapi.cmd.Op2.type == idaapi.o_reg:
                # value needs to be traced back
                b.backtrace(curr_addr, 1)
                # tainted means the reg was xor reg, reg
                # odds are being used to init var.
                if b.tainted != True:
                    last_ref = b.refsLog[-1]
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
                hex_values = hex(data)[2:]
                if hex_values[-1] == "L":
                    hex_values = hex_values[:-1]
                if len(hex_values) % 2:
                    hex_values = "0" + hex_values
                temp = unhexlify(hex_values)
            else:
                temp = '\x00'
                curr_addr = idc.NextHead(curr_addr)
                continue
            # GetFrameSize is not always accurate
            # buffer size will have to be extended manually
            if ebp == True:
                # reverse the buffer
                temp = temp[::-1]
                for c, ch in enumerate(temp):
                    logging.debug("%s %s" % (index-c , ch))
                    str_buff[index - c ] = ch
            if esp == True:
                for c, ch in enumerate(temp):
                    logging.debug("%s %s") % (index-c , ch)
                    str_buff[index + c] = ch
        curr_addr = idc.NextHead(curr_addr)
    if ebp == True:
        str_buff = str_buff[::-1]
        str_buff.pop()
    return str_buff

def format_str(frame_buffer):
    formated = ""
    for index, ch in enumerate(frame_buffer):
        try:
            if ch == "\x00" and frame_buffer[index + 1] != "\x00":
                formated += " "
        except:
            pass
        if ch != "\x00":
            formated += ch
    return formated

start = SelStart()
# SelEnd() returns the address after the selected data.
# The below code changes the current address to the last selected 
end = PrevHead(SelEnd())
frame_size = use_frame_size(start)
frame_buffer = get_strings(start, end, frame_size)
MakeComm(end, format_str(frame_buffer))
