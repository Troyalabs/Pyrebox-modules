#-------------------------------------------------------------------------------
#   Troyalabs Module for PyreBox
#   Module Name: AntiAntiVM
#   Authors: @j0sm1 (JoseMi Holguin) and @bondey_M (Marc Salinas)
#   Version: 0.1 (For now just a PoC)
#   Description: An anti VM detection module for Pyrebox inspired by Idastealth and Pafish
#-------------------------------------------------------------------------------

from __future__ import print_function
from api import CallbackManager
import api
import functools
from api import BP
import pefile

#TEMPORAL
from ipython_shell import start_shell


process_is_created = 0
target_pgd = 0
target_name = ""
target_pid = 0

def opcodes(cpu_index,cpu,pc,next_pc):
	global pyrebox_print
	global target_pgd

	if api.is_kernel_running(cpu_index) == False:
		pgd = api.get_running_process(cpu_index)
		if pgd == target_pgd and pc < 0x500000:
			if cpu.EBX == 0x54474354:
				api.w_r(0,"EBX",0x72657661)
				api.w_r(0,"ECX",0x33333179)
				api.w_r(0,"EDX",0x70796837)
				pyrebox_print("[*] Hypervisor name check %x" % pc)	
				#start_shell()
			elif cpu.EBX == 0x756e6547:
				pyrebox_print("[*] GenuineIntel check %x" % pc)	
			elif cpu.EBX == 0x72695620:
				api.w_r(0,"EAX",0x65746e49)
				api.w_r(0,"EBX",0x6f63206c)
				api.w_r(0,"ECX",0x49206572)
				api.w_r(0,"EDX",0x00003936)
				pyrebox_print("[*] CPU Name check %x" % pc)	
				#start_shell()
			elif cpu.ECX == 0x80000001: 				#Not pretty elegant
				api.w_r(0,"ECX",0x00000000)
				pyrebox_print("[*] Hypervisor bit check %x" % pc)	
			else: 
				pyrebox_print("[*] Unknown Check (TODO) %x" % pc) 
				#start_shell()


def new_proc(pid, pgd, name):
	global process_is_created
	global cm
	
	global target_pgd
	global target_pid
	global target_name

	global pyrebox_print
	if name == "malo.exe":
		target_pgd = pgd
		target_name = name
		target_pid = pid

		process_is_created = 1
		pyrebox_print("[*] Proc created")
		api.start_monitoring_process(target_pgd)
		cm.add_callback(CallbackManager.CONTEXTCHANGE_CB, functools.partial(context_change, pgd, name), name="context_change")
		cm.rm_callback("vmi_new_proc")


def context_change(pgd_target, target_mod_name, old_pgd, new_pgd):
	'''Callback triggered for every context change
		:param target_pgd: This parameter is inserted using functools.partial (see callback registration)
		:param target_mod_name: This parameter is inserted using functools.partial (see callback registration)
		:param old_pgd: This is the first parameter of the callback
		:param new_pgd: This is the second parameter of the callback
	'''
	global cm
	global target_pgd
	global target_pid
	global target_name


	if target_pgd == new_pgd:
		ep = find_ep(target_pgd, target_mod_name)
		if ep is not None:
			pyrebox_print("The entry point for %s is %x\n" % (target_mod_name, ep))
			cm.rm_callback("context_change")
			cm.add_callback(CallbackManager.OPCODE_RANGE_CB, opcodes, name="opcode2_%x" % (target_pid), start_opcode=0x0fa2, end_opcode=0x0fa2)

			############### TODO (hooking VM detection Windows APIs)
			#cm.add_callback(CallbackManager.INSN_BEGIN_CB,ep_hit,addr=ep,pgd=target_pgd)

def update_symbols(cpu_index,cpu):

	global cm
	global target_pgd

	pgd = api.get_running_process(cpu_index)
	start_shell()
	if pgd == target_pgd:
		api.get_symbol_list()
		cm.rm_callback("update_symbols")


def initialize_callbacks(module_hdl, printer):
	global cm
	global pyrebox_print
	from plugins.guest_agent import guest_agent

	pyrebox_print = printer
	cm = CallbackManager(module_hdl)

	guest_agent.copy_file("/home/marc/sdcard/zoo/gen/sample.exe","C:\\ProgramData\\malo.exe")
	cm.add_callback(CallbackManager.CREATEPROC_CB, new_proc, name="vmi_new_proc")
	guest_agent.execute_file("C:\\ProgramData\\malo.exe")


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
				pe_data = api.r_va(pgd, base, 0x1000)
				pe = pefile.PE(data=pe_data)
				ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
				return (base + ep)
			except Exception:
				pyrebox_print("Unable to run pefile on loaded module %s" % name)






############### TODO (hooking VM detection Windows APIs)
def ep_hit(cpu_index,cpu):
	global target_pgd
	api.start_monitoring_process(target_pgd)
	simbols = api.get_symbol_list(target_pgd)			
	for sim in simbols:
		if sim["name"] == "GetDiskFreeSpaceExW" or sim["name"] == "GetDiskFreeSpaceExA":
			pyrebox_print("found! %s" % sim["addr"])
			cm.add_callback(CallbackManager.INSN_BEGIN_CB,GetFreeSpaceCalled,addr=sim["addr"],pgd=target_pgd)
	start_shell()


def GetFreeSpaceCalled(addr,pgd):
	start_shell()
	cm.add_callback(CallbackManager.INSN_BEGIN_CB,my_function,addr=addr,pgd=pgd)

def my_function(cpu_index,cpu):
	start_shell()