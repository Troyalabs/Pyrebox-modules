#-------------------------------------------------------------------------------
#
#   Copyright (C) 2017 Cisco Talos Security Intelligence and Research Group
#
#   PyREBox: Python scriptable Reverse Engineering Sandbox 
#   Author: Xabier Ugarte-Pedrero 
#   
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as
#   published by the Free Software Foundation.
#   
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#   MA 02110-1301, USA.
#   
#-------------------------------------------------------------------------------


#-------------------------------------------------------------------------------
#   Troyalabs Module for PyreBox
#   Module Name: funcap
#   Authors: @j0sm1 (JoseMi Holguin) and @bondey_M (Marc Salinas)
#   Version: 0.1
#   Description: Windows Api Monitor. This module is inspired in funcap module to IDA Pro
#-------------------------------------------------------------------------------

from __future__ import print_function
import sys
import api
import logging
from ipython_shell import start_shell
from api import CallbackManager
from capstone import *
from capstone.x86 import *
from utils import pp_print
import string
from api import BP
import pefile
import functools

#Callback manager
cm = None
procs_created = 0
target_procname = ""
symbols_updated = 0 
#Printer
pyrebox_print = None


#Process to execute
TARGET="pipes.exe"

## CONSTANTS

# minimum length requirement to be ascii
STRING_EXPLORATION_MIN_LENGTH = 4
# length of discovered strings outputted to file and console
STRING_LENGTH = 164
# length of single-line hexdumps in hexdump mode outputted to file and console
HEXMODE_LENGTH = 164
# Max number of instructions to monitor
MAX_INSTRUCTIONS = 100000


if __name__ == "__main__":
	# This message will be displayed when the script is loaded in memory
	print("[*] Loading python module %s" % (__file__))


# The following few functions are adopted from PaiMei by Pedram Amini
# they are here to format and present data in a nice way
# Source: funcap script to IDA Pro (funtions to print format)

def get_ascii_string (data):
	'''
	Retrieve the ASCII string, if any, from data. Ensure that the string is valid by checking against the minimum
	length requirement defined in self.STRING_EXPLORATION_MIN_LENGTH.

	@type  data: Raw
	@param data: Data to explore for printable ascii string

	@rtype:  String
	@return: False on failure, ascii string on discovered string
	'''

	discovered = ""

	for char in data:
		# if we've hit a non printable char, break
		if ord(char) < 32 or ord(char) > 126:
			break

		discovered += char

	if len(discovered) < STRING_EXPLORATION_MIN_LENGTH:
		return False

	return discovered

def get_printable_string (data, print_dots=True):
	'''
	description

	@type  data:       Raw
	@param data:       Data to explore for printable ascii string
	@type  print_dots: Bool
	@param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable

	@rtype:  String
	@return: False on failure, discovered printable chars in string otherwise.
	'''

	discovered = ""

	for char in data:
		if ord(char) >= 32 and ord(char) <= 126:
			discovered += char
		elif print_dots:
			discovered += "."

	return discovered

def get_unicode_string (data):
	'''
	description

	@type  data: Raw
	@param data: Data to explore for printable unicode string

	@rtype:  String
	@return: False on failure, ascii-converted unicode string on discovered string.
	'''

	discovered  = ""
	every_other = True

	for char in data:
		if every_other:
			# if we've hit a non printable char, break
			if ord(char) < 32 or ord(char) > 126:
				break

			discovered += char

		every_other = not every_other

	if len(discovered) < STRING_EXPLORATION_MIN_LENGTH:
		return False

	return discovered

def hex_dump(data):
	'''
	Utility function that converts data into one-line hex dump format.

	@type  data:   Raw Bytes
	@param data:   Raw bytes to view in hex dump

	@rtype:  String
	@return: Hex dump of data.
	'''

	dump = ""

	for byte in data:
		dump  += "%02x " % ord(byte)

	for byte in data:
		if ord(byte) >= 32 and ord(byte) <= 126:
			dump += byte
		else:
			dump += "."

	return dump


def smart_format(raw_data, maxlen, print_dots=True):
	'''
	"Intelligently" discover data behind an address. The address is dereferenced and explored in search of an ASCII
	or Unicode string. In the absense of a string the printable characters are returned with non-printables
	represented as dots (.). The location of the discovered data is returned as well as either "heap", "stack" or
	the name of the module it lies in (global data).
	@param raw_data:    Binary data to format
	@type  print_dots: Bool
	@param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable
	@rtype:  String
	@return: String of data discovered behind dereference.

	Original source code: https://github.com/deresz/funcap/blob/master/funcap.py
	'''

	if not raw_data:
		return 'N/A'

	try_unicode = raw_data[:maxlen * 2]
	try_ascii = raw_data[:maxlen]

	data = raw_data[:maxlen]
	to_strings_file = None

	data_string = get_ascii_string(try_ascii)
	to_strings_file = data_string

	if not data_string:
		data_string = get_unicode_string(try_unicode)
		to_strings_file = data_string

		if not data_string and hexdump:
			data_string = hex_dump(data)

		if not data_string:
			data_string = get_printable_string(data, print_dots)

	return data_string

def initialize_callbacks(module_hdl,printer):
	'''
	Initilize callbacks for this module. 
	'''
	global cm
	global pyrebox_print
	# debug var
	global num_ins
	global logger
	global process_is_created

	logger = logging.getLogger('funcap')
	hdlr = logging.FileHandler('funcap.log')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	logger.addHandler(hdlr)

	# Set level log
	level = 0

	if level == 0:
		logger.setLevel(logging.INFO)
	elif level == 1:
		logger.setLevel(logging.WARNING)
	elif level == 2:
		logger.setLevel(logging.ERROR)
	elif level == 3:
		logger.setLevel(logging.CRITICAL)
	else:
		logger.setLevel(logging.WARNING)

	num_ins=0
	process_is_created = 0
	# Init symbols
	# api.get_symbol_list()
	# Initialize printer function
	pyrebox_print = printer
	pyrebox_print("[*]    Initializing callbacks")

	#Initialize the callback manager
	cm = CallbackManager(module_hdl)
	##
	# Callback for CALL opcode
	##
	cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="vmi_new_proc")
	cm.add_callback(CallbackManager.OPCODE_RANGE_CB,funcap,start_opcode=0xFF,end_opcode=0xFF)
	cm.add_callback(CallbackManager.REMOVEPROC_CB, remove_proc, name="vmi_remove_proc")

	do_set_target(TARGET)
	
	pyrebox_print("[*]    Initialized callbacks")

def clean():
	'''
	Clean up everything. 
	'''
	global cm
	global logger
	print("[*]    Cleaning module")
	cm.clean()
	print ("[*]    Cleaned module")

def find_ep(pgd, proc_name):
	'''Given an address space and a process name, uses pefile module
	   to get its entry point
	'''
	global cm
	global loaded_processes
	import api
	for m in api.get_module_list(pgd):
		name = m["name"]
		base = m["base"]
		# size = m["size"]
		if name == proc_name:
			try:
				pe_data = api.r_va(pgd, base, 0x2000)
				pe = pefile.PE(data=pe_data)
				ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
				return (base + ep)
			except:
				pyrebox_print("Unable to run pefile on loaded module %s" % name)

def do_set_target(line):
	'''Set target process - Custom command

	   Set a target process name. When a process with this name is created,
	   the script will start monitoring context changes and retrieve
	   the module entry point as soon as it is available in memory. Then
	   it will place a breakpoint on the entry point.
	'''
	global pyrebox_print
	global target_procname
	target_procname = line.strip()
	pyrebox_print("Waiting for process %s to start\n" % target_procname)


def context_change(target_pgd, target_mod_name, old_pgd, new_pgd):
	'''Callback triggered for every context change
		:param target_pgd: This parameter is inserted using functools.partial (see callback registration)
		:param target_mod_name: This parameter is inserted using functools.partial (see callback registration)
		:param old_pgd: This is the first parameter of the callback
		:param new_pgd: This is the second parameter of the callback
	'''
	global cm
	global ep

	if target_pgd == new_pgd:
		ep = find_ep(target_pgd, target_mod_name)
		if ep is not None:
			# Add INSB_BEGIN_CB to monitor entry point execution and update the symbols
			cm.add_callback(CallbackManager.INSN_BEGIN_CB,update_symbols,addr=ep,pgd=target_pgd, name="update_symbols")
			pyrebox_print("Set callback in the entry point for PGD: %x is EP: %x\n" % (target_pgd, ep))
			pyrebox_print("The entry point for %s is %x\n" % (target_mod_name, ep))
			cm.rm_callback("context_change")


def new_proc(pid, pgd, name):
	'''
	Process creation callback. Receives 3 parameters:
		:param pid: The pid of the process
		:type pid: int
		:param pgd: The PGD of the process
		:type pgd: int
		:param name: The name of the process
		:type name: str
	'''
	global pyrebox_print
	global procs_created
	global target_procname
	global cm
	global pgd_target
	global process_is_created

	pyrebox_print("New process created! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))
	procs_created += 1
	# For instance, we can start the shell whenever a process is created
	if target_procname != "" and target_procname.lower() in name.lower():
		pgd_target = pgd 
		# At this point, the process has been created, but
		# the main module (and dlls) have not been loaded yet.
		# We put a callback on the context changes, and wait for
		# the process to start executing.
		process_is_created = 1
		# set monitor to target process
		api.start_monitoring_process(pgd_target)
		cm.add_callback(CallbackManager.CONTEXTCHANGE_CB, functools.partial(context_change, pgd, name), name="context_change")
		# In order to start a shell, we just need to call start_shell()
		#pyrebox_print("Starting a shell after the %s process has been created" % name)
		#start_shell()

def remove_proc(pid, pgd, name):
	'''
	Process removal callback. Receives 3 parameters:
		:param pid: The pid of the process
		:type pid: int
		:param pgd: The PGD of the process
		:type pgd: int
		:param name: The name of the process
		:type name: str
	'''
	pyrebox_print("Process removed! pid: %x, pgd: %x, name: %s" % (pid, pgd, name))


def disassemble(addr,cpu_index):
	'''
	Disassemble instruction. Receives 2 parameters:
		:param addr: Address from instruction to disassemble
		:type addr: int
		:param cpu_index: CPU index 
		:type cpu_index: int
	'''

	global logger
	global num_ins

	pgd = api.get_running_process(cpu_index)

	if api.get_os_bits()==32:
		md = Cs(CS_ARCH_X86, CS_MODE_32)
		content = api.r_va(pgd,addr,0x4)
	else:
		md = Cs(CS_ARCH_X86, CS_MODE_64)
		content = api.r_va(pgd,addr,0x6)
	
	md.detail = True
	
	for insn in md.disasm(content, addr):
		
		if insn.mnemonic == "call":

			if len(insn.operands) > 0:
				
				mycpu=api.r_cpu(0)
				
				simbolo=None

				if api.get_os_bits()==32:
					simbolo=api.va_to_sym(pgd,mycpu.EIP)
				else:
					simbolo=api.va_to_sym(pgd,mycpu.RIP)

				if simbolo != None and api.get_os_bits()!=32:

					## Microsoft x64 calling convention
					## 

					logger.info("[API]0x%x:\t%s\t%s\t[RIP]:0x%x\t%s\t[PGD]: %x",insn.address, insn.mnemonic, insn.op_str,mycpu.RIP,simbolo,pgd)
					num_ins = num_ins + 1

					## RCX - Arg 1 

					try:

						rcx_content = api.r_va(pgd,mycpu.RCX,0x100)
						logger.info("[RCX]: 0x%x [Data]: %s", mycpu.RCX,smart_format(rcx_content, 0x100, True))

					except:
						logger.info("[RCX]: 0x%x", mycpu.RCX)

					## RDX - Arg 2 

					try:

						rdx_content = api.r_va(pgd,mycpu.RDX,0x100)
						logger.info("[RDX]: 0x%x [Data]: %s", mycpu.RDX,smart_format(rdx_content, 0x100, True))

					except:
						logger.info("[RDX]: 0x%x", mycpu.RDX)

					## R8 - Arg 3

					try:

						r8_content = api.r_va(pgd,mycpu.R8,0x100)
						logger.info("[R8]: 0x%x [Data]: %s", mycpu.R8,smart_format(r8_content, 0x100, True))

					except:
						logger.info("[R8]: 0x%x", mycpu.R8)

					## R9 - Arg 4

					try:

						r9_content = api.r_va(pgd,mycpu.R9,0x100)
						logger.info("[R9]: 0x%x [Data]: %s", mycpu.R9,smart_format(r9_content, 0x100, True))

					except:
						logger.info("[R9]: 0x%x", mycpu.R9)

					## RAX - return value

					try:
						rax_content = api.r_va(pgd,mycpu.RAX,0x100)
						logger.info("[RAX]: 0x%x [Data]: %s", mycpu.RAX,smart_format(rax_content, 0x100, True))

					except:

						logger.info("[RAX]: 0x%x", mycpu.RAX)


					logger.info("--")

				elif simbolo != None :

					## x86 call conventions 
					# cdecl -> arguments are pushed on the stack in the reverse order. EAX return
					# syscall -> arguments are pushed on the stack right to left.
					# optlink -> arguments are pushed on the stack right to left.
					# ...  
					
					logger.info("[API]0x%x:\t%s\t%s\t[EIP]:0x%x\t%s\t[PGD]: %x",insn.address, insn.mnemonic, insn.op_str,mycpu.EIP,simbolo,pgd)
					num_ins = num_ins + 1

					bytestoread = 0x200

					try:
						eax_content = api.r_va(pgd,mycpu.EAX,bytestoread)
						logger.info("[EAX]: 0x%x [Data]: %s", mycpu.EAX,smart_format(eax_content, bytestoread, True))
						
					except:
						logger.info("[EAX]: 0x%x", mycpu.EAX)

					try:
						ecx_content = api.r_va(pgd,mycpu.ECX,bytestoread)
						logger.info("[ECX]: 0x%x [Data]: %s", mycpu.ECX,smart_format(ecx_content, bytestoread, True))					
						
					except:
						logger.info("[ECX]: 0x%x", mycpu.ECX)

					try:
						edx_content = api.r_va(pgd,mycpu.EDX,bytestoread)
						logger.info("[EDX]: 0x%x [Data]: %s", mycpu.EDX,smart_format(edx_content, bytestoread, True))					
						
					except:
						logger.info("[EDX]: 0x%x", mycpu.EDX)

					try:
						ebp_arg2_content = api.r_va(pgd,mycpu.EBP+8,bytestoread)
						logger.info("[EBP+8]: 0x%x [Data]: %s", mycpu.EBP+8,smart_format(ebp_arg2_content, bytestoread, True))
					except:
						logger.info("[EBP+8]: 0x%x", mycpu.EBP+8)

					try:
						ebp_arg3_content = api.r_va(pgd,mycpu.EBP+12,bytestoread)
						logger.info("[EBP+12]: 0x%x [Data]: %s", mycpu.EBP+12,smart_format(ebp_arg3_content, bytestoread, True))
					except:
						logger.info("[EBP+12]: 0x%x", mycpu.EBP+12)

					try:
						ebp_arg4_content = api.r_va(pgd,mycpu.EBP+16,bytestoread)
						logger.info("[EBP+16]: 0x%x [Data]: %s", mycpu.EBP+16,smart_format(ebp_arg4_content, bytestoread, True))
					except:
						logger.info("[EBP+16]: 0x%x", mycpu.EBP+16)

					try:
						ebp_arg5_content = api.r_va(pgd,mycpu.EBP+20,bytestoread)
						logger.info("[EBP+20]: 0x%x [Data]: %s", mycpu.EBP+20,smart_format(ebp_arg5_content, bytestoread, True))
					except:
						logger.info("[EBP+20]: 0x%x", mycpu.EBP+20)

					try:
						ebp_arg6_content = api.r_va(pgd,mycpu.EBP+24,bytestoread)
						logger.info("[EBP+24]: 0x%x [Data]: %s", mycpu.EBP+24,smart_format(ebp_arg6_content, bytestoread, True))
					except:
						logger.info("[EBP+24]: 0x%x", mycpu.EBP+24)

					logger.info("--")
								   

def funcap(cpu_index,cpu,pc,next_pc):

	'''
		Function to monitor API calls and to resolve symbols. Receives 4 parameters (OPCODE CALLBACK):
		:param addr: Address from instruction to disassemble
		:type addr: int
		:param cpu_index: CPU index 
		:type cpu_index: int
	'''
	
	global num_ins
	global logger
	global pgd_target
	global process_is_created

	if process_is_created == 1 and api.is_kernel_running(cpu_index) == False:
	
		pgd = api.get_running_process(cpu_index)

		if pgd_target == pgd:
			disassemble(pc,cpu_index)

		if num_ins == MAX_INSTRUCTIONS:
			api.stop_monitoring_process(pgd)
			pyrebox_print("[*] Stopped monitoring process")
			num_ins = 0
	
def update_symbols(cpu_index,cpu):
	'''
		Function to update the symbols. Receives 2 parameters (INS CALLBACK):
		:param cpu: CPU context
		:type cpu: X86		
		:param cpu_index: CPU index 
		:type cpu_index: int
	'''

	global cm
	global pgd_target

	pgd = api.get_running_process(cpu_index)

	if pgd == pgd_target:
		api.get_symbol_list()
		cm.rm_callback("update_symbols")
