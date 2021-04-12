#Set the output log file path
logfilepath = "C:\\Users\\test1\\Desktop\\Analyze_CONTI_LOG.txt"

#This IDAPython script resolves the hashed API of the Conti ransomware, logs the called API, and adds a comment to the IDB.
#You should start IDA as a debugger and stopped at an entry point (or other around the EP) and 
#all breakpoints need to be removed before running. It’s designed to be used with File->Script Command.

def GetDecFunc():
    check_address1=idc.get_reg_value("EIP")
    count_loop1=1    
    count_call=0
    while count_loop1 < 9:
        prev_address1 = prev_head(check_address1)
        nem_prev_address1 = print_insn_mnem(prev_address1)
        if nem_prev_address1 == "call":
            count_call+=1
            if count_call == 2:
                found_decryptfunc = get_operand_value(prev_address1,0)
                idc.add_bpt(prev_address1)
                break
        count_loop1+=1
        check_address1 = prev_address1
    return found_decryptfunc

def ReAnalyze():
    minaddress =idc.get_segm_start(idc.get_reg_value("EIP"))
    maxaddress = idc.get_segm_end(idc.get_reg_value("EIP"))
    plan_and_wait(minaddress,maxaddress)

def SearchDecFunc():
    count_searchloop = 1
    found_loadlibrary=None
    llib_ea = idc.get_name_ea_simple("kernel32_LoadLibraryA")
    idc.add_bpt(llib_ea)
    while count_searchloop < 9:
        count_searchloop += 1
        idaapi.continue_process()
        event_code = idc.wait_for_next_event(idc.WFNE_SUSP, -1)
    idaapi.step_until_ret()
    event_code = idc.wait_for_next_event(idc.WFNE_SUSP, -1)
    ReAnalyze()
    retnaddr=GetDecFunc()
    return retnaddr

def SearchDecFuncAndSetBreak(target):
    xrefs = CodeRefsTo(target,1)
    for xref in xrefs:
        return_addr = next_head(xref)
        idc.add_bpt(return_addr)
        idc.add_bpt(xref)

def OutPutLog(string):
    with open(logfilepath, "a") as f:
        f.write("%s\n" % string)

def CheckArg_and_Output(inputfunname,input_eip):
    count_loop=0
    count_push=0
    found_key = None
    found_hashAddr = None
    libname = None
    check_address = input_eip
    tidstr=str(idaapi.get_current_thread())
    call_addr = input_eip
    call_addr_opcode = print_insn_mnem(input_eip)
    if call_addr_opcode == "call":
        input_eip = next_head(input_eip)
    try:
        if(inputfunname == "kernel32_lstrcmpiW"):
            op1addr = next_head(input_eip)
            op1 =  ida_idp.ph_get_operand_info(op1addr,1)
            compare1=get_strlit_contents(op1[1],-1, ida_nalt.STRTYPE_C_16)
            op2addr = next_head(next_head(op1addr))
            op2 =  ida_idp.ph_get_operand_info(op2addr,1)
            compare2=get_strlit_contents(op2[1],-1, ida_nalt.STRTYPE_C_16)
            inputfunname = inputfunname + "(" +str(compare1) + "," + str(compare2) + ")"
        if(inputfunname == "shlwapi_StrStrIW"):
            nextaddr = next_head(input_eip)
            op1 =  ida_idp.ph_get_operand_info(nextaddr,0)
            compare1=get_strlit_contents(op1[2],-1, ida_nalt.STRTYPE_C_16)
            compare2=get_strlit_contents(idc.get_reg_value("EDI"),-1, ida_nalt.STRTYPE_C_16)
            inputfunname = inputfunname + "(" + str(compare2) +","+ str(compare1) + ")"
        if(inputfunname == "kernel32_CreateFileW"):
            nextaddr = next_head(input_eip)
            nextopcode = print_insn_mnem(nextaddr)
            if nextopcode == "push":
                filename=get_strlit_contents(idc.get_reg_value("ESI"),-1, ida_nalt.STRTYPE_C_16)
            else:
                filenameaddr =  ida_idp.ph_get_operand_info(nextaddr,1)
                filename=get_strlit_contents(filenameaddr[1],-1, ida_nalt.STRTYPE_C_16)
            inputfunname = inputfunname + "(" + str(filename) + ")"
        if(inputfunname == "kernel32_GetProcAddress"):
            funcname = get_strlit_contents(idc.get_reg_value("ESI"))
            inputfunname = inputfunname + "(" + str(funcname) + ")"
        if(inputfunname == "kernel32_LoadLibraryA"):
            libname = get_strlit_contents(idc.get_reg_value("ESI"))
            inputfunname = inputfunname + "(" + str(libname) + ")"
    except:
        OutPutLog("[API arg error]")
    while count_loop < 6:
        before_x_address = prev_head(check_address)
        nem_before_x_address = print_insn_mnem(before_x_address)
        if nem_before_x_address == "call":
            call_addr = before_x_address
        if nem_before_x_address == "push":
            if count_push < 1:
                found_hashAddr = print_operand(before_x_address, 0)
                idc.set_cmt(before_x_address, "API = " + inputfunname, 0) 
            elif count_push == 1:
                found_key = print_operand(before_x_address, 0)
                OutPutLog("[" + hex(call_addr) + "][TID:" + tidstr + "]:-->" + inputfunname + "(" + found_hashAddr + ":" + found_key + ")")
                break
            count_push += 1
        count_loop += 1
        check_address = before_x_address

def ResolveAPI(decaddr):
    minaddress = idc.get_inf_attr(INF_MIN_EA)
    maxaddress = idc.get_inf_attr(INF_MAX_EA)
    eip_adddress = idc.get_reg_value("EIP")
    while(eip_adddress >= minaddress and eip_adddress <= maxaddress):
        idaapi.continue_process()
        event_code = idc.wait_for_next_event(idc.WFNE_SUSP, -1)        
        if event_code < 1 or event_code == idc.PROCESS_EXITED:
            break                
        if get_reg_value("EIP") == decaddr:
            idaapi.step_until_ret()
            evt_code = idc.wait_for_next_event(idc.WFNE_SUSP, -1)
        else:
            if print_insn_mnem(get_reg_value("EIP")) == "call":
                idc.step_over()
                evt_code = idc.wait_for_next_event(idc.WFNE_SUSP, -1)
        eax_adddress = idc.get_reg_value("EAX")
        decryptfunctionName = get_name(eax_adddress)
        CheckArg_and_Output(decryptfunctionName, idc.get_reg_value("EIP"))       

def main():
    addr=SearchDecFunc()
    SearchDecFuncAndSetBreak(addr)
    ResolveAPI(addr)

main()
