from idaapi import * 
from idautils import *
from idc import *
import sys
import inspect

'''
Name: 
    backtrace.py
 Version: 
    0.2 
        *   fixed logic in regards to parsing strings in function questionBackItUp
    0.3 *   Added the functionality to trace all references to a register. The previous
            version only monitored MOVs. It can now track most general purpose
            instuctions. It does not compare instruction that contain a control flow
            such as cmp, CMOVE, etc. It also does not track the usage of registers
            pushed onto the stack. 
            
 Author
    alexander<dot>hanel<at>gmail<dot>com

Table of Code Contents
Summary:
	backtrace.py is a class that can be used to backtrace reference of registers and args in IDA. 
	The class relies on string and function argument parsing. Using strings of disassembly 
	presents some problems because we have to account for every scenario of how the data is
	moved. Needless to say I did not account for all of these. I wrote this script to aid 
	break the script. It's still u	in tracking arguments being passed to API calls. There will 
	be plenty of scenarios that should be useful though. 
	
Quick Code Summary:
	Use backtrace(address, operand) to get the backtrace of a register in a function. The first 
	operand value starts at 0 and then 1. "mov     eax, ecx", eax = 0, ecx = 1. Don't use 0 when 
	first calling backtrace() unless there is only 1 operand. The first time backtrace() is called
	it does not check if the values are being moved. "push    eax" is a safe situation when to use 0. 
	To see verbose output enable classobject.verbose = True. This code only account for the selected
	function and it's parents. If we wanted to check for an argument that was passed to the child, 
	which was also passed as an argument to the parent that will need to be coded up by the user. 
	Assume _cdecl & _stdcall

5 Second Demo
	.text:0040EA90 i___MainOfInjectedCode proc near        ; CODE XREF: sub_40ED40+5p
	.text:0040EA90                                         ; _main_inject+5p
	.text:0040EA90
	.text:0040EA90 arg_0     = dword ptr  4
	.text:0040EA90
	.text:0040EA90           push    ebx
	.text:0040EA91           push    ebp
	.text:0040EA92           mov     ebp, [esp+8+arg_0]    ; base address
	.text:0040EA96           push    esi
	.text:0040EA97           push    edi
	.text:0040EA98           call    _GetBaseAddressOfKernel32
	.text:0040EA9D           mov     esi, eax              ; eax = base address of kernel32
	.text:0040EA9F           test    esi, esi
	.text:0040EAA1           jz      short _return         ; something broke
	.text:0040EAA3           push    esi
	.text:0040EAA4           mov     ebx, offset aLoadlibrarya ; "LoadLibraryA"
	.text:0040EAA9           call    i_LookUpAPIAddr
	.text:0040EAAE           push    esi
	.text:0040EAAF           mov     ebx, offset aGetprocaddress ; "GetProcAddress"
	.text:0040EAB4           mov     edi, eax              ; assign address of LoadLibrary
	.text:0040EAB6           call    i_LookUpAPIAddr
	.text:0040EABB           xor     esi, esi
	.text:0040EABD           add     esp, 8
	.text:0040EAC0           cmp     edi, esi
	.text:0040EAC2           jz      short _return         ; something broke
	.text:0040EAC4           cmp     eax, esi
	.text:0040EAC6           jz      short _return         ; something broke
	.text:0040EAC8           push    eax                   ; GetProcAddress
	.text:0040EAC9           push    edi                   ; edi = LoadlibaryA
	.text:0040EACA           mov     ebx, ebp				<- HERE(), we are choosing ebp which is operand 1 
	.text:0040EACC           call    i_RebuildImportTable

Output
	Python>s = Backtrace()
	Python>s.verbose = True
	Python>s.getAll(1)
		0x40eaca mov     ebx, ebp
		0x40ea92 mov     ebp, [esp+8+arg_0]    ; base address

	****** Argument Details ******
	[INFO] Selection in i___MainOfInjectedCode 
	0x40ea92 mov     ebp, [esp+8+arg_0]    ; base address
	[INFO] Selection is argument 1 in i___MainOfInjectedCode
	Called by sub_40ED40
		0x40ed44 push    eax
		0x40ed40 mov     eax, [esp+arg_0]

	Called by _main_inject
		0x40ed54 push    eax
		0x40ed50 mov     eax, [esp+arg_0]
	
Functions:	
   * retApiRef(String_API_Name) - For working with code refs. Pass the string of an API name
       and it will return a list of the address of all cross-references to the API Name. 

   * retxrefs(Data_Address) - For working with data refs. Pass the address of the data and
       it will return in a list all the addresses that xref the data. 
       - Example:
            Python>s.retxrefs(here())  <- here() = .rdata:004120FC byte_4120FC db 48h  
               [4214883, 4214892] <- all xrefs to data address

   * getArgs(FUNCTION_CALL_ADDRESS, STACK_ARG_NUMBER) - For getting the address and operand
       of an argument pushed on to a function. Pass the address of where the function is being called
       from and the count of the argument. Uses a simple string 'push' string search. Will check up to
       10 previous lines. After that is will return None if not found. 
       - Example:
            .text:0040E495           push    eax
            .text:0040E496           add     ecx, 8
            .text:0040E499           call    sub_404FE0
            Python>s.getArgs(0x040E499, 1)
            (4252821, 'eax') <- address of the push and the operand

    * getStack(FUNCTION_ADDRESS) - For getting all variables used on the stack in a function. Returns
		a list that contains each objects used on the stack. 
		- Example:
			.text:0040E1E0 sub_40E1E0 proc near                    ; CODE XREF: sub_40EA50+2Ap
			.text:0040E1E0
			.text:0040E1E0 var_10    = dword ptr -10h
			.text:0040E1E0 var_C     = dword ptr -0Ch
			.text:0040E1E0 var_8     = dword ptr -8
			.text:0040E1E0 var_4     = dword ptr -4
			.text:0040E1E0 arg_0     = dword ptr  4
			.text:0040E1E0 arg_4     = dword ptr  8
			.text:0040E1E0 arg_8     = dword ptr  0Ch
			.text:0040E1E0
			.text:0040E1E0           sub     esp, 10h
			.text:0040E1E3           mov     ecx, [esp+10h+arg_8]
			Python>s.getStack(0x0040E1E0)
			[('var_10', 4, '0x20000400'), ('var_C', 4, '0x20000400'), ('var_8', 4, '0x20000400'), 
			('var_4', 4, '0x20000400'), (' r', 4, '0x400'), ('arg_0', 4, '0x20000400'), ('arg_4', 4, '0x20000400'),
			('arg_8', 4, '0x20000400')] 
			
	* getStackArgs(STACK) - For getting arguments pushed on to the stack. The STACK is the list retured from the 
		function getStack (see above). 
		- Example:
			.text:0040E1E0 sub_40E1E0 proc near                    ; CODE XREF: sub_40EA50+2Ap
			.text:0040E1E0
			.text:0040E1E0 var_10    = dword ptr -10h
			.text:0040E1E0 var_C     = dword ptr -0Ch
			.text:0040E1E0 var_8     = dword ptr -8
			.text:0040E1E0 var_4     = dword ptr -4
			.text:0040E1E0 arg_0     = dword ptr  4
			.text:0040E1E0 arg_4     = dword ptr  8
			.text:0040E1E0 arg_8     = dword ptr  0Ch
			.text:0040E1E0
			.text:0040E1E0           sub     esp, 10h
			.text:0040E1E3           mov     ecx, [esp+10h+arg_8]
			Python>s.getStackArgs( s.getStack(0x0040E1E0))
			[('arg_0', 4, '0x20000400'), ('arg_4', 4, '0x20000400'), ('arg_8', 4, '0x20000400')]
	* printlog() - Used to print when a varaible gets reassinged. This is logged in the list self.refsLog.
	
	* backtrace(ADDRESS, OPERAND_PLACEMENT) - For getting the first reference of a register or stack object
		of a selected operand.  The return is a tupple with the address and the dism. This uses simple string 
		parsing to track when a operand/register/stack object is moved around in a function. Referred to as lastRef
		IMPORTANT please verify the correct number of the operand when selecting. No error checking is done 
		to verify the size. For the following 'mov     eax, ecx', eax is operand 0 and ecx is operand 1. 
		- Example:
			.text:0040E1E0           sub     esp, 10h
			.text:0040E1E3           mov     ecx, [esp+10h+arg_8]
			.text:0040E1E7           push    ebx
			.text:0040E1E8           push    ebp
			.text:0040E1E9           push    esi
			.text:0040E1EA           mov     esi, [esp+1Ch+arg_0]
			.text:0040E1EE           lea     ebx, [esi+28h]
			.text:0040E1F1           lea     eax, [ebx+854h]
			.text:0040E1F7           mov     [esp+1Ch+var_10], eax
			.text:0040E1FB           mov     eax, ecx  <- ecx is chosen. 
			.text:0040E1FD           and     eax, 4]
			Python>s.backtrace(0x0040E1FB, 1)
			(4252131, 'mov     ecx, [esp+10h+arg_8]') <- address and string
			To see the printlog and referenes set class_instance.verbose = True
			Python>s.backtrace(0x0040E1FB, 1)
			0x40e1fb mov     eax, ecx
			0x40e1e3 mov     ecx, [esp+10h+arg_8]
			(4252131, 'mov     ecx, [esp+10h+arg_8]')
		NOTE: Don't choose operand 0 for MOVs during first selection. The code does not check for MOV from 
		operand 0 to operand 1 in the first selection. Might update later. 
		
	* questionBackItUp(RETURN_FROM_backtrace) - For checking if the return from backtrace is passed as an argument
		on the stack. Labled as a lastRef in the code. It returns the stack arugment number if the lastRef was an
		argument. Returns None if it isn't. 
		- Example:
			.text:0040E1E0           sub     esp, 10h
			.text:0040E1E3           mov     ecx, [esp+10h+arg_8]
			.text:0040E1E7           push    ebx
			.text:0040E1E8           push    ebp
			.text:0040E1E9           push    esi
			.text:0040E1EA           mov     esi, [esp+1Ch+arg_0]
			.text:0040E1EE           lea     ebx, [esi+28h]
			.text:0040E1F1           lea     eax, [ebx+854h]
			.text:0040E1F7           mov     [esp+1Ch+var_10], eax
			.text:0040E1FB           mov     eax, ecx  <- ecx is chosen. 
			.text:0040E1FD           and     eax, 4]
			Python>s.questionBackItUp( s.backtrace(0x0040E1FB, 1))
			3 <- argument count.

	* strip(string) - Used for splitting up and parsing operands. I couldn't figure out how to get the one to one
		name between the dism '[esp+1Ch+arg_0]' and the stack name of arg_0. 
		
	* backItUp(RETURN_FROM_backtrace) - For getting all argument address and their operands to a function. This checks 
		all xrefs to a function. The return type is a list that contains a tupple of (address and operand). 
		- Example: 
			The following function is called twice. 
			Python>s.backItUp( s.backtrace(0x0040EACA, 1))
			[(4255044, 'eax'), (4255060, 'eax')]
			To get more details we can enable the verbose which displays more info
			Python>s.backItUp( s.backtrace(here(), 1))
			0x40eaca mov     ebx, ebp
			0x40ea92 mov     ebp, [esp+8+arg_0]    ; base address

			****** Argument Details ******
			[INFO] Selection in i___MainOfInjectedCode 
			0x40ea92 mov     ebp, [esp+8+arg_0]    ; base address
			[INFO] Selection is argument 1 in i___MainOfInjectedCode
			Called by sub_40ED40
				0x40ed44 push    eax
				0x40ed40 mov     eax, [esp+arg_0]

			Called by _main_inject
				0x40ed54 push    eax
				0x40ed50 mov     eax, [esp+arg_0]

			[(4255044, 'eax'), (4255060, 'eax')]
			
	* getAll(OPERAND_NUMBER) - Simple wrapper for backItUp() and backtrace(). It uses the selected address of the
		cursor. Verbose will need to be enabled. 	
		
TO DO List
	1. Forward Trace
	2. Cross-refernce check
	3. Clean up the output.
	4. Trace usage of registers and their sub-register: eax contains ax, ah, al 
'''

class Backtrace():
    def __init__(self):
        self.AlexCanNotDrawAStack = True
        self.registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']
        self.verbose = True
        self.refsLog = []
        self.maxDepth = 25
        self.nonMov = True
        self.nonReg = ''
        self.tainted = False
        
    def debug(self):
        print inspect.currentframe().f_back.f_lineno
        
    def retApiRef(self, apiname):
        'get all xrefs to an api by name'
        apiAddrList = []
        for address in CodeRefsTo(LocByName(apiname),0):
            apiAddrList.append(address)
        return apiAddrList

    def retxrefs(self, address):
        'get xrefs from data return address'
        xrefsList = []
        for xrefs in DataRefsTo(address):
            xrefsList.append(xrefs)
        return xrefsList

    def getArgs(self, address, count):
        'get specified (by count) argument and address'
        pushcount = 0
        instructionMax = 10 + count
        currAddress = PrevHead(address,minea=0)
        while pushcount <= count and instructionMax != 0:
            if 'push' in GetDisasm(currAddress):
                pushcount += 1
                if pushcount == count:
                    return currAddress, GetOpnd(currAddress,0)
            instructionMax -= 1
            currAddress = PrevHead(currAddress,minea=0)
        return None, None 

    def getStack(self,address):
        'gets variables used on the stack'
        # Related reads and/or pointers on stacks in IDA
        # http://zairon.wordpress.com/2008/02/15/idc-script-and-stack-frame-variables-length/
        # https://github.com/moloch--/IDA-Python/blob/master/Stack_Calculator.py
        stackFrame = GetFrame(address)
        lastEntry = GetLastMember(stackFrame)
        count = 0
        stack = []
        while count <= lastEntry:
                localName = GetMemberName(stackFrame,count)
                size = GetMemberSize(stackFrame, count)
                flag = GetMemberFlag(stackFrame, count)
                if localName == None or size == None or flag == -1:
                        count += 1
                        continue 
                stack.append((localName, size, hex(flag)))
                count += size
        # returns stack variable list[tuple(localName, size, hex(flags))]
        return stack

    def getStackArgs(self, stack):
        'returns the args seen locally in a function returned from getStack()'
        # can use len(getStackArgs(stack)) to get arg count 
        for c,x in enumerate(stack):
            if x[0] == ' r':
                # returns stack variable list[tuple(localName, size, hex(flags))]
                return stack[c+1:]
        return None 

    def printlog(self):
        'print log'
        if self.verbose == True:
            for ref in self.refsLog:
                 print '\t', hex(ref[0]), ref[1]
            print
            
    def clearLog(self):
         self.refsLog = []

    def GPRPurpose(self, register):
        if register in ['al', 'ah', 'ax', 'eax', 'rax']:
            return 'accumulator' 
        if register in ['bl', 'bh', 'bx', 'ebx', 'rbx']:
            return 'base'
        if register in ['cl', 'ch', 'cx', 'ecx', 'rcx']:
            return 'counter'
        if register in ['dl', 'dh', 'dx', 'edx', 'rdx']:
            return 'extend'
        if register in ['si', 'esi', 'rsi']:
            return 'source'
        if register in ['di', 'edi', 'rdi']:
            return 'dest'
        if register in ['sp', 'esp', 'rbp']:
            return 'stack'
        if register in ['bp', 'ebp', 'rbp']:
            return 'base'
        if register in ['ip', 'eip', 'rip']:
            return 'instru' 
        return None

    
    def inDism(self, dism, pur):
        s = dism.replace(',','').split()
            # remove mnemonic
        if len(s) > 1:
            del s[0]
        for op in s:
            results = self.GPRPurpose(op)
            if results == None:
                return False
            elif pur == results:
                return True
            
        return False
            
    def backtrace(self, address, operand):
        'find the initial assignment'
        # Will need to bool to track for more than one function, child, parent...
        self.clearLog() # !!! TEST ME. How will this effect other code!!!!
        self.tainted = False
        lastRef = (address, GetDisasm(address))
        self.refsLog.append(lastRef)
        funcStart = GetFunctionAttr(address, FUNCATTR_START)
        var = GetOpnd(address, operand)
        purpose = self.GPRPurpose(var)
        currentAddress = PrevHead(address)
        dism = GetDisasm(currentAddress)
        while(currentAddress >= funcStart):
            # check for reg being used as a pointer [eax]
            for reg in self.registers:
                ptreg = '['+reg+']'
                if var == ptreg:
                    var = reg
                    purpose = self.GPRPurpose(var)
            if var.isdigit() == True:
                tmp = NextHead(currentAddress)
                lastRef = (tmp, GetDisasm(tmp))
                self.refsLog.append(lastRef)
                self.printlog()
                return 
            if 'call' in dism and var == 'eax':
                lastRef = (currentAddress, GetDisasm(currentAddress))
                self.refsLog.append(lastRef)
                self.printlog()
                return
            if var in dism or self.inDism(dism,purpose):
                mnem = GetMnem(currentAddress)
                '''
                Data Transfer -
                Instrustion     Checked         Description
                MOV             X		Move data between general-purpose registers; 
                MOVSX           X		Move and sign extend
                MOVZX 	        X		Move and zero extend
                XCHG 	        X		Exchange
                BSWAP 		X		Byte swap
                XADD 		X		Exchange and add

                Stack Based - 
                PUSH 				Push onto stack
                POP 				Pop off of stack
                PUSHA/PUSHAD 		        Push general-purpose registers onto stack
                POPA/POPAD 			Pop general-purpose registers from stack

                Convert - 
                CWD/CDQ 			Convert word to doubleword/Convert doubleword to quadword
                CBW/CWDE 			Convert byte to word/Convert word to doubleword in EAX register

                Compare - 
                CMPXCHG 			Compare and exchange
                CMPXCHG8B 			Compare and exchange 8 bytes

                Conditional - 
                CMOVE/CMOVZ 		        Conditional move if equal/Conditional move if zero
                CMOVNE/CMOVNZ 		        Conditional move if not equal/Conditional move if not zero
                CMOVA/CMOVNBE 		        Conditional move if above/Conditional move if not below or equal
                CMOVAE/CMOVNB 		        Conditional move if above or equal/Conditional move if not below
                CMOVB/CMOVNAE 		        Conditional move if below/Conditional move if not above or equal
                CMOVBE/CMOVNA 		        Conditional move if below or equal/Conditional move if not above
                CMOVG/CMOVNLE 		        Conditional move if greater/Conditional move if not less or equal
                CMOVGE/CMOVNL 		        Conditional move if greater or equal/Conditional move if not less
                CMOVL/CMOVNGE 		        Conditional move if less/Conditional move if not greater or equal
                CMOVLE/CMOVNG 		        Conditional move if less orequal/Conditional move if not greater
                CMOVC 				Conditional move if carry
                CMOVNC 				Conditional move if not carry
                CMOVO 				Conditional move if overflow
                CMOVNO 				Conditional move if not overflow
                CMOVS 				Conditional move if sign (negative)
                CMOVNS 				Conditional move ifnot sign (non-negative)
                CMOVP/CMOVPE 		        Conditional move if parity/Conditional move if parity even
                CMOVNP/CMOVPO 		        Conditional move if not parity/Conditional move if parity odd 
                '''
                if mnem in ['mov', 'movsx', 'movzx','xchg']:
                    if var in GetOpnd(currentAddress,0) or self.inDism(GetOpnd(currentAddress,0), purpose):
                        var = GetOpnd(currentAddress,1)
                        purpose = self.GPRPurpose(var)
                        lastRef = (currentAddress, GetDisasm(currentAddress))
                        self.refsLog.append(lastRef)
                if self.nonMov  == True:
                    if mnem in ['bswap']:
                        if var in GetOpnd(currentAddress,0) or self.inDism(GetOpnd(currentAddress,0), purpose):
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                    ''' XADD Example
                        Assembly Code 
                        .code
                        main PROC
                                call Clrscr
                                mov	eax,10000h		; EAX = 10000h
                                mov	ebx,40000h		; EBX = 40000h
                                call	DumpRegs
                                xadd eax, ebx
                                call DumpRegs
                                exit
                        main ENDP

                      Output - before  
                      EAX=00010000  EBX=00040000  ECX=00000000  EDX=00401005
                      ESI=00000000  EDI=00000000  EBP=0018FF94  ESP=0018FF8C
                      EIP=00401024  EFL=00000212  CF=0  SF=0  ZF=0  OF=0  AF=1  PF=0
                      Output - after   
                      EAX=00050000  EBX=00010000  ECX=00000000  EDX=00401005
                      ESI=00000000  EDI=00000000  EBP=0018FF94  ESP=0018FF8C
                      EIP=0040102C  EFL=00000206  CF=0  SF=0  ZF=0  OF=0  AF=0  PF=1
                    '''
                    if mnem in ['xadd']:
                        # exchanged/temporary value. Not modified. See example above
                        if var in GetOpnd(currentAddress,1) or self.inDism(GetOpnd(currentAddress,1), purpose):
                            var = GetOpnd(currentAddress,0)
                            purpose = self.GPRPurpose(var)
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                        # calculated value. basically add
                        elif var in GetOpnd(currentAddress,0) or self.inDism(GetOpnd(currentAddress,0), purpose):
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef) 
                    # Logical Instructions
                    if mnem in ['and', 'or', 'xor', 'not']:
                        if var in GetOpnd(currentAddress,0) or self.inDism(GetOpnd(currentAddress,0), purpose):
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                            if mnem in ['xor'] and GetOpnd(currentAddress,0) == GetOpnd(currentAddress,1):
                                self.tainted = True
                    # Shift and Rotate Instructions
                    if mnem in ['sar', 'shr', 'sal', 'shl', 'shrd', 'shld', 'ror', 'rol', 'rcr', 'rcl']:
                        if var in GetOpnd(currentAddress,0) or self.inDism(GetOpnd(currentAddress,0), purpose):
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                    # Binary Arithmetic Instructions, dest source based
                    if mnem in ['add', 'adc', 'sub', 'sbb', 'inc', 'dec', 'neg']:
                        if var in GetOpnd(currentAddress,0) or self.inDism(GetOpnd(currentAddress,0), purpose):
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                    # Binary Arthimetic Instructions - quadword operand
                    if mnem in ['imul', 'mul', 'idiv', 'div']:
                        if var in GetOpnd(currentAddress,0) or self.inDism(GetOpnd(currentAddress,0), purpose):
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                            
                    '''
                    Miscellaneous Instructions
                    Instrustion     Checked         Description
                    LEA             X               Load effective address
                    NOP             n/a             No operation
                    UD2             n/a             Undefined instruction.
                     ..                             The instruction is provided to allow software
                     ..                             to test an invalid opcode exception handler.
                    XLAT/XLATB      X               Table lookup translation
                    CPUID           X               Processor identification
                    MOVBE           n/a             Move data after swapping data bytes.
                     ..                             Atom processor specific  
                    '''
                    if mnem in ['lea']:
                        if self.inDism(GetOpnd(currentAddress,0), purpose):
                        #if var in GetOpnd(currentAddress,0): REMOVE
                            lastRef = (currentAddress, GetDisasm(currentAddress))   
                            self.refsLog.append(lastRef)
                    if mnem in ['cpuid']:
                        if self.inDism(var, 'accumulator') or self.inDism(var, 'counter'):
                        # if var in ['eax', 'ax', 'ebx', 'bx', 'ecx', 'cx', 'edx', 'dx']:     # 64-BIT-UPDATE-NEEDED REMOVE
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                            self.printlog()
                            return
                    if mnem in ['xlat', 'xlatb']:
                        if self.inDism(var, 'accumulator'):
                        #if var in ['eax', 'ah' 'al']: REMOVE
                            lastRef = (currentAddress, GetDisasm(currentAddress))
                            self.refsLog.append(lastRef)
                            self.printlog()
                            return 
            currentAddress = PrevHead(currentAddress)
            dism = GetDisasm(currentAddress)
        self.printlog()
        return 

    def questionBackItUp(self, lastRef):
        'checks if last ref is an argument'
        argNum = None
        address, dism = lastRef
        # get value, assuming mov* and lea, check backtrace() for the logic
        if ';' in dism:
            dism = dism[:dism.find(';')-1] # used to strip out comments
        value = dism.split()[-1]
        var = self.strip(value)
        args = self.getStackArgs(self.getStack(address))
        for each in var:
            for index, arg in enumerate(args):
                if each == arg[0]:
                    argNum = index + 1
                    if self.verbose == True:
                        print '[INFO] Selection is argument %s in %s' % (argNum, GetFunctionName(address))
                    return argNum
        return argNum
   
    def strip(self, string):
        'sorry could not figure out to get the stack name vs the ascii name in ida'
        for x in '[]+.*':
            string = string.replace(x, ' ')
        for x in self.registers:
            string = string.replace(x, ' ')
        return string.split()
                           
    def backItUp(self,lastRef):
        allArgRefs = []
        address, dism = lastRef
        if self.verbose == True:
            print '****** Argument Details ******'
            print '[INFO] Selection in %s ' %  GetFunctionName(address)
            print hex(address), dism      
        xrefs = ''
        arg = self.questionBackItUp(lastRef)
        # if arg returns None, the lastRef is not an argument
        if arg != None:
            for funcAddr in CodeRefsTo(GetFunctionAttr(address, FUNCATTR_START),0):
                if funcAddr == None:
                    continue 
                argAddr, oper = self.getArgs(funcAddr, arg)
                if argAddr == None or oper == None:
                    if self.verbose == True:
                        print '[ERROR]: Could not get args for', hex(funcAddr)
                    continue
                allArgRefs.append((argAddr, oper))
                if self.verbose == True:
                    print 'Called by %s' % GetFunctionName(funcAddr)
                self.backtrace(argAddr, 0)
        else:
            if self.verbose == True:
                print 'Selection is not an argument'
        return allArgRefs
    
    def getAll(self, op):
        self.backItUp(self.backtrace(here(),op))
            
'''    
if __name__ == "__main__":
    s = Backtrace()
    s.verbose = True
    print 'updated'
'''
