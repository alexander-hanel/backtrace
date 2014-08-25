"""
Author:
    Alexander Hanel
Date:
    20140814
Version:
    .9 - still being testing
Summary:
    Examples of using the backtrace libary to rebuild strings

TODO:
    Completely rebuild the stack and local arguments of a function. 

Notes:
    idaapi.o_phrase # Memory Ref [Base Reg + Index Reg]

    o_phrase   =  idaapi.o_phrase    #  Memory Ref [Base Reg + Index Reg]    phrase
    o_displ    =  idaapi.o_displ     #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr

Useful Reads
    http://smokedchicken.org/2012/05/ida-rename-local-from-a-script.html
    http://zairon.wordpress.com/2008/02/15/idc-script-and-stack-frame-variables-length/
    
"""
import sys, os
from binascii import unhexlify
from math import log
sys.path.append(os.path.realpath(__file__ + "/../../"))
from backtrace import *

def use_frame_size(start):
    return idc.GetFrameSize(start)

def get_strings(start, end, size):
    b = Backtrace()
    esp = False
    ebp = False
    b.verbose = False
    str_buff = list('\x00' * size)
    curr_addr = end
    while curr_addr >= start:
        idaapi.decode_insn(curr_addr)
        if idaapi.cmd.itype == idaapi.NN_mov and \
           idaapi.cmd.Op1.type == idaapi.o_displ:
            # get the frame pointer address, used as index
            if int(idaapi.cmd.Op1.addr) > size:
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
                if b.tainted == False:
                    last_ref = b.refsLog[-1]
                    idaapi.decode_insn(int(last_ref[0]))
                    data = idaapi.cmd.Op2.value
                else:
                    # tracked variable has been set to zero by xor reg, reg
                    curr_addr = idc.PrevHead(curr_addr)
                    continue
            elif idaapi.cmd.Op2.type != idaapi.o_imm:
                curr_addr = idc.PrevHead(curr_addr)
                continue
            else:
                data = idaapi.cmd.Op2.value 
            # read the data
            if data != 0:
                size_in_bytes = int(log(data, 256)) + 1
            # unhexlify(hex(data)[2:)) Hack, didn't want to read the struct docs
            if data:
                temp = unhexlify(hex(data)[2:])
            else:
                temp = '\x00'
                curr_addr = idc.PrevHead(curr_addr)
                continue                
            if ebp == True:
                temp = temp[::-1]
                for c, ch in enumerate(temp):
                    str_buff[index - c ] = ch
            if esp == True:
                for c, ch in enumerate(temp):
                    str_buff[index + c ] = ch
        curr_addr = idc.PrevHead(curr_addr)
    
    if ebp == True:
        str_buff = str_buff[::-1]
        str_buff.insert(0, '\x00')
    return str_buff

start = SelStart()
# SelEnd() returns the address after the selected data.
# The below code changes the current address to the last selected 
end = PrevHead(SelEnd())
frame_size = use_frame_size(start)
xxx = get_strings(start, end, frame_size)
yyy =  ''.join(xxx).replace("\x00", " ")
sys.stdout.write(yyy.replace("  ", ""))
