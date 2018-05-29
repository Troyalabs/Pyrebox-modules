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
import pefile

#TEMPORAL
from ipython_shell import start_shell   # this will not be needed   			 

sample_to_upload = "/path/to/the/local/sample.exe" 
upload_path = "C:\\ProgramData\\"
sample_name = "malo.exe"        

process_is_created = 0
target_pgd = 0
rdtsc_val_hi=0
rdtsc_val_lo=0

def rdtsc_opcode_call(cpu_index,cpu,pc,next_pc):
	global pyrebox_print
	global target_pgd
	global rdtsc_val_lo
	global rdtsc_val_hi

	
	if api.is_kernel_running(cpu_index) == False:
		pgd = api.get_running_process(cpu_index)
		if pgd == target_pgd and pc < 0x500000:
			if rdtsc_val_lo == 0:
				pyrebox_print("[*] first rdtsc call %x" % pc)	
				rdtsc_val_lo = cpu.EAX
				rdtsc_val_hi = cpu.EDX
			else:
				pyrebox_print("[*] new rdtsc check! %x" % pc)	
				rdtsc_val_lo = rdtsc_val_lo + 500  # this just works for pafish ~cos it has a sleep(500), need to find a more general aproach
				api.w_r(0,"EAX",rdtsc_val_lo)
				api.w_r(0,"EDX",rdtsc_val_hi)


def cpuid_opcode_call(cpu_index,cpu,pc,next_pc):
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


def new_process_created(pid, pgd, name):
	global process_is_created
	global cm
	global target_pgd
	global sample_name
	global pyrebox_print


	if name == sample_name:
		target_pgd = pgd

		process_is_created = 1
		pyrebox_print("[*] Process created")
		api.start_monitoring_process(target_pgd)
		cm.add_callback(CallbackManager.CONTEXTCHANGE_CB, functools.partial(context_change, pgd, name), name="context_change")
		cm.rm_callback("vmi_new_proc")


def context_change(pgd_target, target_mod_name, old_pgd, new_pgd):
	global cm
	global target_pgd


	if target_pgd == new_pgd:
		ep = find_ep(target_pgd, target_mod_name)
		if ep is not None:
			pyrebox_print("The entry point for %s is %x\n" % (target_mod_name, ep))
			cm.rm_callback("context_change")
			# Add a callback for the CPUID opcode
			cm.add_callback(CallbackManager.OPCODE_RANGE_CB, cpuid_opcode_call, name="opcode1_cpuid", start_opcode=0x0fa2, end_opcode=0x0fa2)
			# Add a callback for the RDTSC opcode
			cm.add_callback(CallbackManager.OPCODE_RANGE_CB, rdtsc_opcode_call, name="opcode2_rdtsc", start_opcode=0x0f31, end_opcode=0x0f31)



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


def clean():
	'''
	Clean up everything. 
	'''
	global cm
	global pyrebox_print
	pyrebox_print("[*]    Cleaning module")
	cm.clean()
	pyrebox_print("[*]    Cleaned module")


def initialize_callbacks(module_hdl, printer):
	global cm
	global pyrebox_print
	global sample_to_upload
	global upload_path
	global sample_name

	from plugins.guest_agent import guest_agent

	pyrebox_print = printer
	cm = CallbackManager(module_hdl)

	# Push the sample from de host to de guest
	guest_agent.copy_file(sample_to_upload,upload_path+sample_name)
	# Create a Callback for every new process create to catch de sample when executed
	cm.add_callback(CallbackManager.CREATEPROC_CB, new_process_created, name="vmi_new_proc")
	# Run the sample uploaded to the VM
	guest_agent.execute_file(upload_path+sample_name)

