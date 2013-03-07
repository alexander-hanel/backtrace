from idaapi import * 
import idautils
import idc
import sys

'''
Name: 
    backtrace.py
 Version: 
    0.2 
        * fixed logic in regards to parsing strings in function questionBackItUp
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
'''

class Backtrace():
    def __init__(self):
            self.AlexCanNotDrawAStack = True
            self.registers = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']
            self.verbose = False
            self.refsLog = []
            self.maxDepth = 25
            
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
        self.refsLog = []
    
    def backtrace(self, address, operand):
        'find the initial assignment'
        lastRef = (address, GetDisasm(address))
        self.refsLog.append(lastRef)
        funcStart = GetFunctionAttr(address, FUNCATTR_START)
        var = GetOpnd(address, operand)
        currentAddress = PrevHead(address)
        dism = GetDisasm(currentAddress)
        while(currentAddress >= funcStart):
            # check for reg being used as a pointer [eax]
            for reg in self.registers:
                ptreg = '['+reg+']'
                if var == ptreg:
                    var = reg
            if var.isdigit() == True:
                tmp = NextHead(currentAddress)
                lastRef = (tmp, GetDisasm(tmp))
                self.refsLog.append(lastRef)
                self.printlog()
                return lastRef
            if 'call' in dism and var == 'eax':
                lastRef = (currentAddress, GetDisasm(currentAddress))
                self.refsLog.append(lastRef)
                self.printlog()
                return lastRef
            if var in dism:
                #lastRef = (currentAddress, GetDisasm(currentAddress))
                mnem = GetMnem(currentAddress)
                if 'mov' in mnem or 'lea' in mnem:
                    if GetOpnd(currentAddress,0) == var:
                        var = GetOpnd(currentAddress,1)
                        lastRef = (currentAddress, GetDisasm(currentAddress))
                        self.refsLog.append(lastRef)
            currentAddress = PrevHead(currentAddress)
            dism = GetDisasm(currentAddress)
        self.printlog()
        return lastRef

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
