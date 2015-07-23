/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2014 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/* tvc - The tool for bugs detection in the process of tainted data
 * propagation (based on DBI Intel PIN).
 */

#include "pin.H"
#include <fstream>
#include <iostream>
#include <sstream>
#include <list>

int disable_instrumenting = 0;

struct RoutineAccessList {
    ADDRINT routine_addr;
    std::list<UINT32> access_list;
    ADDRINT routine_stack_base;
    ADDRINT routine_stack_current;
    bool has_stack_access; /* routine has access to stack frames of previous routines */
};
struct SectionBoundaries {
    ADDRINT section_start;
    ADDRINT section_end;
};
struct HeapAllocated {
    ADDRINT heap_start;
    ADDRINT heap_end;
};
struct StackAllocated {
    ADDRINT stack_start;
    ADDRINT stack_end;
};

struct RoutineArgs {
    ADDRINT routine_addr;
    UINT32 arg_number;
};

StackAllocated stack_allocated;
std::list<HeapAllocated> heap_allocated;
std::list<SectionBoundaries> section_boundaries;
std::list<UINT32> byte_tainted_addr;
std::list<REG> regsTainted;
std::list<ADDRINT> addr_list;
std::list<string> func_names;
std::list<RoutineAccessList> rtns_list;
std::list<RoutineArgs> rtns_args_list;
RoutineAccessList rtn_current;
ADDRINT size_to_allocate = 0;
ADDRINT routine_addr_to_return = 0;

KNOB<string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool",
    "i", "tainted_syscalls.in", "specify tainted syscalls file to find entry points");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "results.out", "specify output results file name");
KNOB<BOOL>   KnobDll(KNOB_MODE_WRITEONCE,  "pintool",
    "no_dll", "1", "ignore trace in shared dlls");
ofstream OutFile;

INT32 Usage()
{
    cerr << "-i <syscalls_list> - file that contains syscalls \
            list which process tainted data \
            (PTAL tainted_syscalls.in for example)." << endl;
    cerr << "-i <syscalls_list> - file that contains syscalls \
            list which process tainted data \
            (PTAL tainted_syscalls.in for example). default [tainted_syscalls.in]" << endl;
    cerr << "-o <log_file> - file to write results. default [results.out]" << endl;
    cerr << "-no_dll 1 - tvc will not consider code in shared dll. default [1]" << endl;
    return -1;
}

bool checkAlreadyRegTainted(REG reg)
{
  list<REG>::iterator i;

  for(i = regsTainted.begin(); i != regsTainted.end(); i++){
    if (*i == reg) {
      return true;
    }
  }
  return false;
}

VOID removeMemTainted(UINT32 addr)
{
  byte_tainted_addr.remove(addr);
  OutFile << std::hex << "\t\t\t" << addr << " is now freed" << std::endl;
}

VOID addMemTainted(UINT32 addr)
{
  byte_tainted_addr.push_back(addr);
  rtn_current.access_list.push_back(addr);
  OutFile << std::hex << "\t\t\t" << addr << " is now tainted" << std::endl;
}

bool taintReg(REG reg)
{
  if (checkAlreadyRegTainted(reg) == true){
    OutFile << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
    return false;
  }

  switch(reg){

    case REG_EAX:  regsTainted.push_front(REG_EAX);
    case REG_AX:   regsTainted.push_front(REG_AX);
    case REG_AH:   regsTainted.push_front(REG_AH);
    case REG_AL:   regsTainted.push_front(REG_AL);
         break;

    case REG_EBX:  regsTainted.push_front(REG_EBX);
    case REG_BX:   regsTainted.push_front(REG_BX);
    case REG_BH:   regsTainted.push_front(REG_BH);
    case REG_BL:   regsTainted.push_front(REG_BL);
         break;

    case REG_ECX:  regsTainted.push_front(REG_ECX);
    case REG_CX:   regsTainted.push_front(REG_CX);
    case REG_CH:   regsTainted.push_front(REG_CH);
    case REG_CL:   regsTainted.push_front(REG_CL);
         break;

    case REG_EDX:  regsTainted.push_front(REG_EDX);
    case REG_DX:   regsTainted.push_front(REG_DX);
    case REG_DH:   regsTainted.push_front(REG_DH);
    case REG_DL:   regsTainted.push_front(REG_DL);
         break;

    case REG_EDI:  regsTainted.push_front(REG_EDI);
    case REG_DI:   regsTainted.push_front(REG_DI);
         break;

    case REG_ESI:  regsTainted.push_front(REG_ESI);
    case REG_SI:   regsTainted.push_front(REG_SI);
         break;

    default:
      OutFile << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
      return false;
  }
  OutFile << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
  return true;
}

bool removeRegTainted(REG reg)
{
  switch(reg){

    case REG_EAX:  regsTainted.remove(REG_EAX);
    case REG_AX:   regsTainted.remove(REG_AX);
    case REG_AH:   regsTainted.remove(REG_AH);
    case REG_AL:   regsTainted.remove(REG_AL);
         break;

    case REG_EBX:  regsTainted.remove(REG_EBX);
    case REG_BX:   regsTainted.remove(REG_BX);
    case REG_BH:   regsTainted.remove(REG_BH);
    case REG_BL:   regsTainted.remove(REG_BL);
         break;

    case REG_ECX:  regsTainted.remove(REG_ECX);
    case REG_CX:   regsTainted.remove(REG_CX);
    case REG_CH:   regsTainted.remove(REG_CH);
    case REG_CL:   regsTainted.remove(REG_CL);
         break;

    case REG_EDX:  regsTainted.remove(REG_EDX);
    case REG_DX:   regsTainted.remove(REG_DX);
    case REG_DH:   regsTainted.remove(REG_DH);
    case REG_DL:   regsTainted.remove(REG_DL);
         break;

    case REG_EDI:  regsTainted.remove(REG_EDI);
    case REG_DI:   regsTainted.remove(REG_DI);
         break;

    case REG_ESI:  regsTainted.remove(REG_ESI);
    case REG_SI:   regsTainted.remove(REG_SI);
         break;

    default:
      return false;
  }
  OutFile << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
  return true;
}

VOID print_list (std::list<UINT32> addr_list) {
    list<UINT32>::iterator i;
    OutFile << "[Available: ";
    for(i = addr_list.begin(); i != addr_list.end(); i++)
        OutFile << std::hex << "0x" << *i <<" ";

    OutFile << "]\n";
}

bool check_tainted_boundaries(UINT32 addr) {
    /* check boundaries, vuln? */
    list<UINT32>::iterator i;
    std::list<RoutineAccessList>::iterator m;
    std::list<UINT32>::iterator access_list_it;

    /* check stack access */
    if (addr <= stack_allocated.stack_start &&
        addr >= stack_allocated.stack_end) {
        if (addr >= rtn_current.routine_stack_current &&
                addr < rtn_current.routine_stack_base) {
                    OutFile << "correct access in routine stack frame (local vars)" << endl;
                    return true; /* correct access in routine stack frame */
        } else if (rtn_current.has_stack_access == true) {
            for (m = rtns_list.begin(); m != rtns_list.end(); m++) {
                for (access_list_it = m->access_list.begin();
                        access_list_it != m->access_list.end(); access_list_it++) {
                            if (addr == *access_list_it) {
                                OutFile << "correct access to routine arg" << endl;
                                return true; /* correct access to routine arg */
                            }
                }
            }
            OutFile << "incorrect access to stack of prev. routines " << endl;
            return false; /* incorrect access to stack of previous routines */
        } else {
            OutFile << "incorrect access to stack of prev. routines  or ret. addr" << endl;
            return false /* incorrect access to stack of previous routines */;
        }
    }

    /* check heap access */
    for (i = rtn_current.access_list.begin(); i != rtn_current.access_list.end(); i++) {
        if (addr == *i) {
            OutFile << "correct access to heap" << endl;
            return true; /* correct access to heap */
        }
    }
    /* check heap access to some other routine */
    for (m = rtns_list.begin(); m != rtns_list.end(); m++) {
        for (access_list_it = m->access_list.begin();
                access_list_it != m->access_list.end(); access_list_it++) {
                    if (addr == *access_list_it) {
                        OutFile << std::hex << "incorrect access to heap of routine: "
                                << m->routine_addr << endl;
                        return false; /* correct access to routine arg */
                    }
        }
    }
    OutFile << "correct access to some mem. region" << endl;
    return true;
}

VOID handle_other_instr(ADDRINT instr_addr) {
    if (instr_addr == routine_addr_to_return) {
       OutFile << "Unexpectedly returned from routine " << instr_addr
               << " " << routine_addr_to_return << endl;
        for (ADDRINT i = rtn_current.routine_stack_base;
             i < rtn_current.routine_stack_base + 4; i++) {
            removeMemTainted(i); /* taint return address */
        }
        rtns_list.pop_back();
        rtn_current = rtns_list.back();
        routine_addr_to_return = 0;
    }
}

VOID OnStackChangeIf(ADDRINT sp, ADDRINT addrInfo)
{
    if (routine_addr_to_return !=0)
        handle_other_instr(addrInfo);
    if (sp > stack_allocated.stack_start)
        stack_allocated.stack_start = sp;
    if (sp < stack_allocated.stack_end)
        stack_allocated.stack_end = sp;
    /*OutFile << "Esp = " << std::hex << sp << " at "
            << addrInfo << endl; */
    rtn_current.routine_stack_current = sp;
    /*OutFile << "Total stack size = " << std::hex
            << stack_allocated.stack_start - stack_allocated.stack_end
            << endl; */
}

VOID ReadMem(UINT32 insAddr, UINT32 opCount, REG reg_r, UINT32 memOp, ADDRINT esp) {
  //OutFile << "called from ReadMem ";
  list<UINT32>::iterator i;
  list<RoutineAccessList>::iterator j;
  UINT32 addr = memOp;
  handle_other_instr(insAddr);
  OnStackChangeIf(esp, insAddr);
  if (opCount != 2)
    return;

  for(i = byte_tainted_addr.begin(); i != byte_tainted_addr.end(); i++) {
      if (addr == *i) {
          print_list(rtn_current.access_list);
        OutFile << std::hex << "[READ in " << addr << "]\t" << insAddr << std::endl;
        taintReg(reg_r);
        /* check that tainted data is actually accessible from current routine */
        if (!check_tainted_boundaries(addr))
            OutFile << std::hex << "[VULN read in " << addr << "] at " << insAddr << std::endl;
        return;
      }
  }
  /* if mem != tained and reg == taint => free the reg */
  if (checkAlreadyRegTainted(reg_r)){
    OutFile << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << std::endl;
    removeRegTainted(reg_r);
  }

}

VOID WriteMem(UINT32 insAddr, UINT32 opCount, REG reg_r, UINT32 memOp, ADDRINT esp)
{
  //OutFile << "called from WriteMem ";
  list<UINT32>::iterator i;
  list<RoutineAccessList>::iterator j;
  UINT32 addr = memOp;
  handle_other_instr(insAddr);
  OnStackChangeIf(esp, insAddr);
  if (opCount != 2)
    return;
  for(i = byte_tainted_addr.begin(); i != byte_tainted_addr.end(); i++){
      if (addr == *i) {
        OutFile << std::hex << "[WRITE in " << addr << "]\t" << insAddr << std::endl;
        /* check that tainted data is actually accessible from current routine */
        if (!check_tainted_boundaries(addr))
            OutFile << std::hex << "[VULN write in " << addr << "] at " << insAddr << std::endl;

        if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
          removeMemTainted(addr);

        return ;
      }
  }
  if (checkAlreadyRegTainted(reg_r)){
    OutFile << std::hex << "[WRITE in " << addr << "]\t" << insAddr << std::endl;
    addMemTainted(addr);
  }

}

VOID spreadRegTaint(UINT32 insAddr, UINT32 opCount, REG reg_r, REG reg_w, ADDRINT esp)
{
  //OutFile << "called from spreadRegTaint ";
  handle_other_instr(insAddr);
  OnStackChangeIf(esp, insAddr);
  if (opCount != 2)
    return;
  if (REG_valid(reg_w)){
    if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
      OutFile << "[SPREAD]\t\t" << insAddr  << std::endl;
      OutFile << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
      removeRegTainted(reg_w);
    }
    else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
      OutFile << "[SPREAD]\t\t" << insAddr << std::endl;
      OutFile << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
      taintReg(reg_w);
    }
  }
}

VOID print_rtns_list() {
    std::list<RoutineAccessList>::iterator i;
    OutFile << "Current routines list : ";
    for(i = rtns_list.begin(); i != rtns_list.end(); i++) {
        OutFile << i->routine_addr << " ";
    }
    OutFile << "]" << endl;
}

VOID calls_handler(ADDRINT call_addr, ADDRINT target_addr, ADDRINT arg0,
                   ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4,
                   ADDRINT esp) {
    list<RoutineArgs>::iterator j;
    OutFile << "Calling routine at " << call_addr
            << " to " << target_addr
            << " arg0=" << arg0 << " arg1=" << arg1
            << " arg2=" << arg2 << " arg3=" << arg3
            << " arg4=" << arg4 << " esp= " << esp << endl;
    ADDRINT args[5];
    args[0] = arg0;
    args[1] = arg1;
    args[2] = arg2;
    args[3] = arg3;
    args[4] = arg4;
    handle_other_instr(call_addr);
    routine_addr_to_return = call_addr + 0x5;

    rtns_list.pop_back();
    rtn_current.routine_stack_current = esp;
    rtns_list.push_back(rtn_current);

    rtn_current.routine_addr = target_addr;
    rtn_current.routine_stack_base = esp - 4;
    for (ADDRINT i = rtn_current.routine_stack_base;
         i < esp; i++) {
        addMemTainted(i); /* taint return address */
    }
    /* get args count */
    for (j = rtns_args_list.begin(); j != rtns_args_list.end(); j++) {
        if (j->routine_addr == call_addr) {
            OutFile << "Params counts: " << j->arg_number << endl;
            break;
        }
    }
    rtn_current.access_list.clear();
    rtn_current.has_stack_access = false;
    /* handle input params */
    for (UINT32 k = 0; k < j->arg_number; k++) {
        if (k > 4) /* now we support max 5 routine args */
            break;
        std::list<HeapAllocated>::iterator heap_it;
        for (heap_it = heap_allocated.begin();
             heap_it != heap_allocated.end(); heap_it++) {
                 if (args[k] >= heap_it->heap_start && args[k] <= heap_it->heap_end) {
                     for (ADDRINT heap_addr = heap_it->heap_start;
                          heap_addr <= heap_it->heap_end; heap_addr++) {
                         rtn_current.access_list.push_back(heap_addr);
                     }
                     break;
                 }
        }
        if (args[k] <= stack_allocated.stack_start
            && args[k] >= stack_allocated.stack_end) {
            rtn_current.has_stack_access = true;
        }
    }
    rtns_list.push_back(rtn_current);

    OutFile << "Saving " << rtn_current.routine_addr << endl;
    OutFile << "Switched to routine " << rtn_current.routine_addr << endl;
    print_rtns_list();
}

void calls_handler_rtn(ADDRINT rtn_addr, ADDRINT rtn_value) {
    OutFile << "Routine return at " << rtn_addr
            << " rtn value =" << rtn_value << endl;
    print_rtns_list();
    rtns_list.pop_back();
    print_rtns_list();
    routine_addr_to_return = -1;
    if (rtn_current.routine_addr == 0xFFFFFFFE) {
        OutFile << "Back to system dll ?" << endl;
        return;
    }
    for (ADDRINT i = rtn_current.routine_stack_base;
         i < rtn_current.routine_stack_base + 4; i++) {
        removeMemTainted(i); /* untaint return address */
    }
    /* is heap returned ? */
    RoutineAccessList rtn_tmp = rtns_list.back();
    list<UINT32>::iterator i;
    for (i = rtn_current.access_list.begin(); i != rtn_current.access_list.end(); i++) {
        if (rtn_value == *i) {
            OutFile << "heap returned" << endl;
            while (i!= rtn_current.access_list.end()) {
                rtn_tmp.access_list.push_back(*i);
                i++;
            }
            break;
        }
    }
    rtn_current = rtn_tmp;
    OutFile << "The following memory available for routine "
            << rtn_current.routine_addr << ":\n\t";
    print_list(rtn_current.access_list);
    OutFile << "Current routine is " << rtn_current.routine_addr << "\n";
    OutFile << "---------------------------------------------\n";
}

// Pin calls this function every time a new rtn is executed
VOID Routine(RTN rtn, VOID *v)
{
    if (disable_instrumenting == 1)
        return;
    bool handled = false;
    PIN_LockClient();
    IMG img = IMG_FindByAddress(RTN_Address(rtn));
    PIN_UnlockClient();

    if(!IMG_Valid(img))
      return;
    if(KnobDll.Value() && !IMG_IsMainExecutable(img))
      return;
    RTN_Open(rtn);

    rtn_current.routine_addr = -2;
    rtn_current.access_list.clear();
    OutFile << "Saving loader routine" << endl;
    rtns_list.push_front(rtn_current);

    /* For each instruction of the routine */
    for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        handled = false;
          if (INS_IsProcedureCall(ins)) {
              ADDRINT target = 0;
              if (INS_IsDirectBranchOrCall(ins))
                  target = INS_DirectBranchOrCallTargetAddress(ins);
              else
                  continue;
              RoutineArgs rtn_args_info;
              rtn_args_info.routine_addr = INS_Address(ins);
              rtn_args_info.arg_number = 0;
              INS ins_tmp = INS_Prev(ins);
              while (INS_Opcode(ins_tmp) == XED_ICLASS_PUSH) {
                  /* TODO: add pusha/pushfd etc.*/
                  rtn_args_info.arg_number ++;
                  ins_tmp = INS_Prev(ins_tmp);
              }
              OutFile << "addr = " << rtn_args_info.routine_addr << " " << rtn_args_info.arg_number << endl;
              rtns_args_list.push_back(rtn_args_info);
              INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)calls_handler,
                IARG_ADDRINT, INS_Address(ins),
                IARG_ADDRINT, target,
                IARG_FUNCARG_CALLSITE_VALUE, 0,
                IARG_FUNCARG_CALLSITE_VALUE, 1,
                IARG_FUNCARG_CALLSITE_VALUE, 2,
                IARG_FUNCARG_CALLSITE_VALUE, 3,
                IARG_FUNCARG_CALLSITE_VALUE, 4,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
              handled = true;
          } else if (INS_IsRet(ins)) {
              INS_InsertCall(
                ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)calls_handler_rtn,
                IARG_ADDRINT, INS_Address(ins),
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);
              handled = true;
          } else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
              INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, 0),
                IARG_MEMORYOP_EA, 0,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
              handled = true;
          } else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
                IARG_ADDRINT, INS_Address(ins),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_OperandReg(ins, 1),
                IARG_MEMORYOP_EA, 0,
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
              handled = true;
          } else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
                IARG_ADDRINT, INS_Address(ins),
                IARG_UINT32, INS_OperandCount(ins),
                IARG_UINT32, INS_RegR(ins, 0),
                IARG_UINT32, INS_RegW(ins, 0),
                IARG_REG_VALUE, REG_STACK_PTR,
                IARG_END);
              handled = true;
          } else if (INS_RegWContain(ins, REG_STACK_PTR)) {
              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnStackChangeIf,
                               IARG_REG_VALUE, REG_STACK_PTR,
                               IARG_ADDRINT, INS_Address(ins),
                               IARG_END);
              handled = true;
          }
          if (handled == false) {
              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)handle_other_instr,
                             IARG_ADDRINT, INS_Address(ins),
                             IARG_END);
          }
    }

    RTN_Close(rtn);
}

VOID Fini(INT32 code, VOID *v)
{
    OutFile.close();
}

VOID Before_fread(ADDRINT ret_addr, ADDRINT pMem, ADDRINT ElementSize, ADDRINT Count, ADDRINT File)
{
    ADDRINT addr_to_compare = 0;
    ret_addr = ret_addr - 0x6; /* sub length of call */
    for (std::list<ADDRINT>::iterator it = addr_list.begin() ; it != addr_list.end(); ++it) {
        addr_to_compare = *it;
        if (addr_to_compare == ret_addr) {
            OutFile << "Calling tainted fread at: " << addr_to_compare
                    << " ptr=" << pMem << " element size=" << ElementSize << " count=" << Count  << endl;
            Count = Count * ElementSize;
            disable_instrumenting = 1;
            for (UINT32 i = 0; i < Count; i++)
                byte_tainted_addr.push_back(pMem+i);

            OutFile << "[TAINT]\t\t\tbytes tainted from "
                      << std::hex << "0x" << pMem << " to 0x"
                      << pMem+Count << " (via fread)"<< std::endl;
        }
    }
}

VOID After_fread(CHAR * name, ADDRINT ret)
{
    OutFile << "After: " << name << " returns " << hex << ret << endl;
    disable_instrumenting = 0;
    /* TODO: check if not success */
}

void Before_malloc(ADDRINT addr_to_return, ADDRINT arg1) {
    addr_to_return = addr_to_return - 0x6; /* sub length of call */
    OutFile << "Calling malloc at " << std::hex << addr_to_return << endl;
    size_to_allocate = arg1;

}

VOID After_malloc(ADDRINT ret, ADDRINT rtn_addr) {
  if (ret) {
      OutFile << "[INFO]\t\tmalloc(" << size_to_allocate << ") = " << std::hex
                << ret << std::endl;
      if (rtn_current.routine_addr == 0xFFFFFFFE)
          return;
      OutFile << "Saving new memory space for " << rtn_current.routine_addr << endl;
      HeapAllocated ha;
      ha.heap_start = ret;
      ADDRINT j;
      for (j = 0; j <= size_to_allocate; j++) {
          rtn_current.access_list.push_back(ret+j);
      }
      ha.heap_end = ret + j;
      heap_allocated.push_back(ha);
      rtns_list.pop_back();
      rtns_list.push_back(rtn_current);
  } else {
      OutFile << "[INFO]\t\tmalloc failed(" << size_to_allocate << ") = "
                << std::hex << ret << std::endl;
  }
}

VOID Image(IMG img, VOID *v)
{
    SectionBoundaries sb;
    // Walk through image sections to set boundaries
    if (IMG_Valid(img) && KnobDll.Value() && IMG_IsMainExecutable(img)) {
        OutFile <<"Image name:" << IMG_Name(img) << endl;
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
        {
            OutFile << " Section: " << SEC_Name(sec)
                    << " Address: " << SEC_Address(sec)
                    << " Type: " << SEC_Type(sec)
                    << " Size: " << SEC_Size(sec)
                    << endl;
            sb.section_start = SEC_Address(sec);
            sb.section_end = SEC_Address(sec) + SEC_Size(sec);
            section_boundaries.push_back(sb);
        }
    }

    PIN_InitSymbols();
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym))
    {
        string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
        PIN_LockClient();
        //  Find the fread() function.
        if (undFuncName == "fread")
        {
            RTN allocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym));
            OutFile << "Find fread at: " << IMG_LowAddress(img) + SYM_Value(sym) << endl;
            if (RTN_Valid(allocRtn))
            {
                // Instrument to print the input argument value and the return value.
                RTN_Open(allocRtn);

                RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)Before_fread,
                               IARG_FUNCARG_CALLSITE_VALUE, 0,
                               IARG_FUNCARG_CALLSITE_VALUE, 1,
                               IARG_FUNCARG_CALLSITE_VALUE, 2,
                               IARG_FUNCARG_CALLSITE_VALUE, 3,
                               IARG_FUNCARG_CALLSITE_VALUE, 4,
                               IARG_END);
                RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)After_fread,
                               IARG_ADDRINT, "fread",
                               IARG_FUNCRET_EXITPOINT_VALUE,
                               IARG_END);

                RTN_Close(allocRtn);
            }
        }
        PIN_UnlockClient();
    }
    RTN allocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(allocRtn)) {
        OutFile << "Find malloc at: " << RTN_Address(allocRtn) << endl;
        // Instrument to print the input argument value and the return value.
        RTN_Open(allocRtn);

        RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)Before_malloc,
                        IARG_FUNCARG_CALLSITE_VALUE, 0,
                        IARG_FUNCARG_CALLSITE_VALUE, 1,
                        IARG_ADDRINT, RTN_Address(allocRtn),
                        IARG_END);
        RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)After_malloc,
                        IARG_FUNCRET_EXITPOINT_VALUE,
                        IARG_ADDRINT, RTN_Address(allocRtn),
                        IARG_END);

        RTN_Close(allocRtn);
    }
}

void fromFileToArray(const std::string & fileName)
{
  std::string line;
  std::string token;
  ADDRINT value;

  std::ifstream inFile(fileName.c_str());

  while(getline(inFile, line))
  {
      istringstream ss(line);
      int i = 0;
      while(std::getline(ss, token, ' ')) {
            if (i == 0) {
                func_names.push_back(token);
            } else {
                istringstream (token) >> std::hex >> value;
                addr_list.push_back(value);
            }
            i++;
        }
  }
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    /* read file and load all tainted input points in the list*/
    OutFile.open(KnobOutputFile.Value().c_str());
    fromFileToArray(KnobInputFile.Value().c_str());
    /* open log file */
    for (std::list<ADDRINT>::iterator it = addr_list.begin() ; it != addr_list.end(); ++it) {
        OutFile << "Tainted data entry point syscall address: " << std::hex << *it << endl;
    }
    stack_allocated.stack_start = 0x0;
    stack_allocated.stack_end = 0xFFFFFFFF;
    IMG_AddInstrumentFunction(Image, 0);
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_StartProgram();
    PIN_AddFiniFunction(Fini, 0);
    return 0;
}
