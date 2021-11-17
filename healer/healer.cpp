//----------------------------------------------------------------------------
//
// Sample of monitoring an application for compatibility problems
// and automatically correcting them.
//
// Copyright (C) Microsoft Corporation, 2000-2001.
//
//----------------------------------------------------------------------------

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <iostream>
#include <string>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <dbgeng.h>

#include "nlohmann/json.hpp"

#include <map>
#include <vector>

#include "out.hpp"

typedef struct _BB_INFO
{
    unsigned int voff;
    unsigned int foff;
    unsigned int instr_size;
    unsigned char instr[4];
} BB_INFO;

typedef unsigned int PC_SIZE;

typedef struct _COV_MOD_INFO
{
    std::map<unsigned int, BB_INFO *> bb_info_map;
    char module_name[1024];
    char full_path[0x200];
    ULONG64 image_base;
    ULONG64 image_end;
    unsigned int rva_size;
    unsigned int mod_id;
    std::vector<unsigned int> bb_trace;
} COV_MOD_INFO;

FILE *g_debug_output_fp = NULL;

std::vector<COV_MOD_INFO *> cov_mod_info_list;
unsigned int g_cov_mod_count = 0;

int is_crash = 0;
bool patch_to_binary = false;

unsigned int server_sock_port = 11241;

std::map<unsigned int, unsigned int> exit_bb_list;

PCSTR g_SymbolPath;
char g_CommandLine[8 * MAX_PATH];
BOOL g_Verbose;
BOOL g_NeedVersionBps;

char g_pre_command[8 * MAX_PATH] = {0};
char g_wait_for_dll[500] = {0};

IDebugClient *g_Client;
IDebugControl *g_Control;
IDebugDataSpaces *g_Data;
IDebugRegisters *g_Registers;
IDebugSymbols *g_Symbols;

struct BREAKPOINT
{
    IDebugBreakpoint *Bp;
    ULONG Id;
};

BREAKPOINT g_GetVersionBp;
BREAKPOINT g_GetVersionRetBp;
BREAKPOINT g_GetVersionExBp;
BREAKPOINT g_GetVersionExRetBp;

ULONG g_EaxIndex = DEBUG_ANY_ID;
ULONG g_EipIndex = DEBUG_ANY_ID;
OSVERSIONINFO g_OsVer;
DWORD g_VersionNumber;
ULONG64 g_OsVerOffset;

PCSTR UNUSUAL_EVENT_MSG = "An unusual event occurred.  Ignore it?";
PCSTR UNUSUAL_EVENT_TITLE = "Unhandled Event";

int isFuzzMode = 0;

#include <TlHelp32.h>

DWORD dwDebugeePid = 0;

COV_MOD_INFO *get_cov_mod_info_by_module_name(char *mod_name);

BOOL KillProcess(DWORD ProcessId)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessId);
    if (hProcess == NULL)
        return FALSE;
    if (!TerminateProcess(hProcess, 0))
        return FALSE;
    return TRUE;
}

bool GetModuleList(DWORD dwPId)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32 = {sizeof(MODULEENTRY32)};
    // 1. 创建一个模块相关的快照句柄
    hModuleSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE, // 指定快照的类型
        dwPId);            // 指定进程
    if (hModuleSnap == INVALID_HANDLE_VALUE)
        return false;

    // 2. 通过模块快照句柄获取第一个模块信息
    if (!Module32First(hModuleSnap, &me32))
    {
        CloseHandle(hModuleSnap);
        return false;
    }

    // 3. 循环获取模块信息
    do
    {
        COV_MOD_INFO *cmi = get_cov_mod_info_by_module_name(me32.szModule);
        if (cmi != NULL)
        {
            if (!isFuzzMode)
            {
                printf("add cmi base:%p, size:%x, name:%s, full path:%s\n", me32.modBaseAddr, me32.modBaseSize, me32.szModule, me32.szExePath);
            }

            cmi->image_base = (ULONG64)me32.modBaseAddr;
            cmi->image_end = cmi->image_base + cmi->rva_size;

            strcpy(cmi->full_path, me32.szExePath);
        }

    } while (Module32Next(hModuleSnap, &me32));

    // 4. 关闭句柄并退出函数
    CloseHandle(hModuleSnap);
}

COV_MOD_INFO *get_cov_mod_info_by_pc(unsigned int pc)
{
    COV_MOD_INFO *ret = NULL;
    for (int i = 0; i < cov_mod_info_list.size(); i++)
    {
        COV_MOD_INFO *cmi = cov_mod_info_list[i];
        unsigned int start = cmi->image_base;
        unsigned int end = cmi->image_end;

        if (pc >= start && pc <= end)
        {
            ret = cmi;
            break;
        }
    }

    return ret;
}

COV_MOD_INFO *get_cov_mod_info_by_module_name(char *mod_name)
{
    COV_MOD_INFO *ret = NULL;
    for (int i = 0; i < cov_mod_info_list.size(); i++)
    {
        COV_MOD_INFO *cmi = cov_mod_info_list[i];
        unsigned int start = cmi->image_base;
        unsigned int end = cmi->image_end;

        if (stricmp(mod_name, cmi->module_name) == NULL)
        {
            ret = cmi;
            break;
        }
    }

    return ret;
}

COV_MOD_INFO *reset_cmi_info()
{
    COV_MOD_INFO *ret = NULL;
    for (int i = 0; i < cov_mod_info_list.size(); i++)
    {
        COV_MOD_INFO *cmi = cov_mod_info_list[i];
        cmi->bb_trace.clear();
        cmi->image_base = 0;
        cmi->image_end = 0;
        cmi->full_path[0] = '\0';
    }

    return ret;
}

int do_patch_file(char *lpFileName, COV_MOD_INFO *cmi)
{
    int count = 0;
    HANDLE hFile = CreateFile(lpFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    while (INVALID_HANDLE_VALUE == hFile)
    {
        KillProcess(dwDebugeePid);
        Sleep(500);

        if (!isFuzzMode)
        {
            std::cout << "File could not be opened.";
            TCHAR *lpMsgBuf;
            FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                              FORMAT_MESSAGE_FROM_SYSTEM,
                          NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0,
                          NULL);
            puts(lpMsgBuf);
        }
        hFile = CreateFile(lpFileName, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }

    DWORD dwFileSize = GetFileSize(hFile, NULL);

    HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (NULL == hFileMap)
    {
        CloseHandle(hFile);
        return -1;
    }

    PVOID pvFile = MapViewOfFile(hFileMap, FILE_MAP_WRITE, 0, 0, 0);

    if (NULL == pvFile)
    {
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return false;
    }

    char *file_base_addr = (char *)pvFile;

    for (size_t j = 0; j < cmi->bb_trace.size(); j++)
    {
        BB_INFO *bi = cmi->bb_info_map[cmi->bb_trace[j]];
        memcpy(file_base_addr + bi->foff, bi->instr, bi->instr_size);
        count++;
    }

    UnmapViewOfFile(pvFile);
    CloseHandle(hFileMap);
    CloseHandle(hFile);

    return count;
}

int patch_to_binary_file()
{

    FILE *proc_map_fp = fopen("maps.txt", "w");
    int count = 0;
    for (int i = 0; i < cov_mod_info_list.size(); i++)
    {
        COV_MOD_INFO *cmi = cov_mod_info_list[i];
        fprintf(proc_map_fp, "%s, 0x%llx\n", cmi->full_path, cmi->image_base);
        if (cmi->bb_trace.size() != 0)
        {
            count += do_patch_file(cmi->full_path, cmi);
        }
    }
    fclose(proc_map_fp);
    return count;
}

void save_all_trace()
{

    COV_MOD_INFO *ret = NULL;
    for (int i = 0; i < cov_mod_info_list.size(); i++)
    {
        COV_MOD_INFO *cmi = cov_mod_info_list[i];

        char bb_file_name[0x100] = {0};
        sprintf(bb_file_name, "%s.trace", cmi->module_name);

        FILE *pfile = fopen(bb_file_name, "w");

        for (size_t i = 0; i < cmi->bb_trace.size(); i++)
        {
            fprintf(pfile, "0x%lx\n", cmi->bb_trace[i]);
        }

        fflush(pfile);
        fclose(pfile);
    }
}

ULONG64 g_TraceFrom[3];

//----------------------------------------------------------------------------
//
// Utility routines.
//
//----------------------------------------------------------------------------

SOCKET ConnectSocket;

int init_tcp_client()
{

    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR)
    {
        std::cout << "WSAStartup Failed with error: " << iResult << std::endl;
        return 1;
    }

    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET)
    {
        std::cout << "Error at socket(): " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    sockaddr_in addrServer;
    addrServer.sin_family = AF_INET;
    InetPton(AF_INET, "127.0.0.1", &addrServer.sin_addr.s_addr);

    addrServer.sin_port = htons(server_sock_port);
    memset(&(addrServer.sin_zero), '\0', 8);

    iResult = connect(ConnectSocket, (SOCKADDR *)&addrServer, sizeof(addrServer));
    if (iResult == SOCKET_ERROR)
    {
        closesocket(ConnectSocket);
        std::cout << "Unable to connect to server: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    int recvTimeout = 3000 * 1000; //30s
                                   // setsockopt(ConnectSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&recvTimeout, sizeof(int));
}

void clean_resource()
{
    // Clean up any resources.
    if (g_Control != NULL)
    {
        g_Control->Release();
    }
    if (g_Data != NULL)
    {
        g_Data->Release();
    }
    if (g_Registers != NULL)
    {
        g_Registers->Release();
    }
    if (g_Symbols != NULL)
    {
        g_Symbols->Release();
    }
    if (g_Client != NULL)
    {
        //
        // Request a simple end to any current session.
        // This may or may not do anything but it isn't
        // harmful to call it.
        //

        g_Client->EndSession(DEBUG_END_PASSIVE);

        g_Client->Release();
    }
}

void Exit(int Code, _In_ _Printf_format_string_ PCSTR Format, ...)
{

    // Output an error message if given.
    if (Format != NULL)
    {
        va_list Args;

        va_start(Args, Format);
        vfprintf(stderr, Format, Args);
        va_end(Args);
    }

    exit(Code);
}

void Print(_In_ _Printf_format_string_ PCSTR Format, ...)
{
    va_list Args;
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);
}

void dump_stack_trace(void)
{
    HRESULT Status;
    PDEBUG_STACK_FRAME Frames = NULL;
    int Count = 8;

    ULONG Filled;

    Frames = new DEBUG_STACK_FRAME[Count];
    if (Frames == NULL)
    {
        Exit(1, "Unable to allocate stack frames\n");
    }

    if ((Status = g_Control->GetStackTrace(0, 0, 0, Frames, Count, &Filled)) != S_OK)
    {
        Exit(1, "GetStackTrace failed, 0x%X\n", Status);
    }

    if (!isFuzzMode)
    {
        printf("\nFirst %d frames of the call stack:\n", Filled);
    }

    Count = Filled;

    ULONG index;
    ULONG64 base;

    FILE *pfile = fopen("stacktrace.txt", "w"); //以写的方式打开C.txt文件。

    for (size_t i = 0; i < Count; i++)
    {
        // printf("InstructionOffset: %p ", Frames[i].InstructionOffset);
        // printf("ReturnOffset: %p\n", Frames[i].ReturnOffset);

        g_Symbols->GetModuleByOffset(Frames[i].InstructionOffset, 0, &index, &base);

        fprintf(pfile, "%p\n", Frames[i].InstructionOffset);
    }

    fflush(pfile);
    fclose(pfile);

    pfile = fopen("crashinfo.txt", "w"); //以写的方式打开C.txt文件。

    DEBUG_VALUE reg = {0};
    g_Registers->GetValue(g_EipIndex, &reg);

    fprintf(pfile, "pc: 0x%lx\n", reg.I32);

    fprintf(pfile, "[code %p -- %p]\n", reg.I32 - 0x20, reg.I32 - 0x20 + 0x100);

    unsigned char code[0x100] = {0};
    ULONG res = 0;
    g_Data->ReadVirtual(reg.I32 - 0x20, code, sizeof(code), &res);

    for (size_t i = 0; i < res; i++)
    {
        fprintf(pfile, "%02x ", code[i]);
    }
    fflush(pfile);
    fclose(pfile);

    delete[] Frames;
}

void save_status()
{
    FILE *pfile = fopen("tracer.status", "w");

    if (is_crash)
    {
        fprintf(pfile, "crash");
    }
    else
    {
        fprintf(pfile, "normal");
    }

    fflush(pfile);
    fclose(pfile);
}

void save_target_process_pid(unsigned int pid)
{
    FILE *pfile = fopen("target.pid", "w");
    fprintf(pfile, "%u\n", pid);
    fclose(pfile);
}

//----------------------------------------------------------------------------
//
// Healing routines.
//
//----------------------------------------------------------------------------

char *getFileNameFromPath(char *path, char separator)
{
    if (path != nullptr)
    {
        for (size_t i = strlen(path); i > 0; --i)
        {
            if (path[i - 1] == separator)
            {
                return &path[i];
            }
        }
    }

    return path;
}

void add_module_loaded_info(char *fpath, ULONG64 base)
{
    char *fname = getFileNameFromPath(fpath, '\\');
    COV_MOD_INFO *cmi = get_cov_mod_info_by_module_name(fname);
    if (cmi != NULL)
    {
        if (cmi->image_base != 0)
        {
            printf("found mutiple %s, pre addr:%p, now:%p\n", cmi->module_name, cmi->image_base, base);
            return;
        }

        cmi->image_base = base;
        cmi->image_end = base + cmi->rva_size;
        strcpy(cmi->full_path, fpath);
    }
}

//----------------------------------------------------------------------------
//
// Event callbacks.
//
//----------------------------------------------------------------------------

class EventCallbacks : public DebugBaseEventCallbacks
{
public:
    // IUnknown.
    STDMETHOD_(ULONG, AddRef)
    (
        THIS);
    STDMETHOD_(ULONG, Release)
    (
        THIS);

    // IDebugEventCallbacks.
    STDMETHOD(GetInterestMask)
    (
        THIS_
            _Out_ PULONG Mask);

    STDMETHOD(Breakpoint)
    (
        THIS_
            _In_ PDEBUG_BREAKPOINT Bp);
    STDMETHOD(Exception)
    (
        THIS_
            _In_ PEXCEPTION_RECORD64 Exception,
        _In_ ULONG FirstChance);
    STDMETHOD(CreateProcess)
    (
        THIS_
            _In_ ULONG64 ImageFileHandle,
        _In_ ULONG64 Handle,
        _In_ ULONG64 BaseOffset,
        _In_ ULONG ModuleSize,
        _In_ PCSTR ModuleName,
        _In_ PCSTR ImageName,
        _In_ ULONG CheckSum,
        _In_ ULONG TimeDateStamp,
        _In_ ULONG64 InitialThreadHandle,
        _In_ ULONG64 ThreadDataOffset,
        _In_ ULONG64 StartOffset);
    STDMETHOD(LoadModule)
    (
        THIS_
            _In_ ULONG64 ImageFileHandle,
        _In_ ULONG64 BaseOffset,
        _In_ ULONG ModuleSize,
        _In_ PCSTR ModuleName,
        _In_ PCSTR ImageName,
        _In_ ULONG CheckSum,
        _In_ ULONG TimeDateStamp);
    STDMETHOD(SessionStatus)
    (
        THIS_
            _In_ ULONG Status);
};

STDMETHODIMP_(ULONG)
EventCallbacks::AddRef(
    THIS)
{
    // This class is designed to be static so
    // there's no true refcount.
    return 1;
}

STDMETHODIMP_(ULONG)
EventCallbacks::Release(
    THIS)
{
    // This class is designed to be static so
    // there's no true refcount.
    return 0;
}

STDMETHODIMP
EventCallbacks::GetInterestMask(
    THIS_
        _Out_ PULONG Mask)
{
    *Mask =
        DEBUG_EVENT_BREAKPOINT |
        DEBUG_EVENT_EXCEPTION |
        DEBUG_EVENT_CREATE_PROCESS |
        DEBUG_EVENT_LOAD_MODULE |
        DEBUG_EVENT_SESSION_STATUS;
    return S_OK;
}

STDMETHODIMP
EventCallbacks::Breakpoint(
    THIS_
        _In_ PDEBUG_BREAKPOINT Bp)
{

    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP
EventCallbacks::Exception(
    THIS_
        _In_ PEXCEPTION_RECORD64 Exception,
    _In_ ULONG FirstChance)
{
    UCHAR Instr;
    ULONG Done;
    // We want to handle these exceptions on the first
    // chance to make it look like no exception ever
    // happened.  Handling them on the second chance would
    // allow an exception handler somewhere in the app
    // to be hit on the first chance.
    if (!FirstChance)
    {

        return DEBUG_STATUS_NO_CHANGE;
    }

    if (Exception->ExceptionCode == STATUS_BREAKPOINT)
    {

        COV_MOD_INFO *cmi = get_cov_mod_info_by_pc(Exception->ExceptionAddress);

        if (cmi == NULL)
        {
            GetModuleList(dwDebugeePid);
            cmi = get_cov_mod_info_by_pc(Exception->ExceptionAddress);
        }

        if (cmi != NULL)
        {

            BB_INFO *bi = cmi->bb_info_map[Exception->ExceptionAddress - cmi->image_base];

            if (!isFuzzMode)
            {
                printf("exec-bb: %s!0x%lx\n", cmi->module_name, bi->voff);
            }

            if (exit_bb_list[bi->voff] == 1)
            {
                if (!isFuzzMode)
                {
                    printf("exit-bb: %s!0x%lx\n", cmi->module_name, bi->voff);
                }

                g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "q", DEBUG_EXECUTE_ECHO);
                return DEBUG_STATUS_NO_DEBUGGEE;
            }

            cmi->bb_trace.push_back(bi->voff);

            if (g_Data->WriteVirtual(Exception->ExceptionAddress, bi->instr,
                                     bi->instr_size, &Done) != S_OK ||
                Done != bi->instr_size)
            {
                return DEBUG_STATUS_NO_CHANGE;
            }
        }
        else
        {
            printf("bb not found !!!: 0x%lx\n", Exception->ExceptionAddress);
        }

        return DEBUG_STATUS_GO;
    }

    if (Exception->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
        dump_stack_trace();
        is_crash = 1;

        g_Client->SetOutputCallbacks(&g_OutputCb);
        g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "r", DEBUG_EXECUTE_ECHO);
        g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "u @eip", DEBUG_EXECUTE_ECHO);

        if (!isFuzzMode)
        {
            char input_cmd[0x200];
            while (1)
            {
                printf("quit-to-exit> ");
                std::cin.getline(input_cmd, 0x200);
                if (!strcmp(input_cmd, "quit"))
                {
                    break;
                }
                g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, input_cmd, DEBUG_EXECUTE_ECHO);
            }
        }

        g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "kb 8", DEBUG_EXECUTE_ECHO);
        g_Client->SetOutputCallbacks(NULL);

        g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "q", DEBUG_EXECUTE_ECHO);

        return DEBUG_STATUS_NO_DEBUGGEE;
    }

    return DEBUG_STATUS_IGNORE_EVENT;
}

STDMETHODIMP
EventCallbacks::CreateProcess(
    THIS_
        _In_ ULONG64 ImageFileHandle,
    _In_ ULONG64 Handle,
    _In_ ULONG64 BaseOffset,
    _In_ ULONG ModuleSize,
    _In_ PCSTR ModuleName,
    _In_ PCSTR ImageName,
    _In_ ULONG CheckSum,
    _In_ ULONG TimeDateStamp,
    _In_ ULONG64 InitialThreadHandle,
    _In_ ULONG64 ThreadDataOffset,
    _In_ ULONG64 StartOffset)
{
    UNREFERENCED_PARAMETER(ImageFileHandle);
    UNREFERENCED_PARAMETER(Handle);
    UNREFERENCED_PARAMETER(ModuleSize);
    UNREFERENCED_PARAMETER(ModuleName);
    UNREFERENCED_PARAMETER(CheckSum);
    UNREFERENCED_PARAMETER(TimeDateStamp);
    UNREFERENCED_PARAMETER(InitialThreadHandle);
    UNREFERENCED_PARAMETER(ThreadDataOffset);
    UNREFERENCED_PARAMETER(StartOffset);

    dwDebugeePid = GetProcessId((HANDLE)Handle);

    save_target_process_pid(dwDebugeePid);
    return DEBUG_STATUS_GO;
}

STDMETHODIMP
EventCallbacks::LoadModule(
    THIS_
        _In_ ULONG64 ImageFileHandle,
    _In_ ULONG64 BaseOffset,
    _In_ ULONG ModuleSize,
    _In_ PCSTR ModuleName,
    _In_ PCSTR ImageName,
    _In_ ULONG CheckSum,
    _In_ ULONG TimeDateStamp)
{
    UNREFERENCED_PARAMETER(ImageFileHandle);
    UNREFERENCED_PARAMETER(ModuleSize);
    UNREFERENCED_PARAMETER(ModuleName);
    UNREFERENCED_PARAMETER(CheckSum);
    UNREFERENCED_PARAMETER(TimeDateStamp);

    char *fname = getFileNameFromPath((char *)ImageName, '\\');

    if (!isFuzzMode)
    {
        printf("load %s!\n", fname);
    }

    if (strcmp(g_wait_for_dll, fname) == 0 && g_pre_command[0])
    {
        system(g_pre_command);
    }

    return DEBUG_STATUS_GO;
}

STDMETHODIMP
EventCallbacks::SessionStatus(
    THIS_
        _In_ ULONG SessionStatus)
{
    // A session isn't fully active until WaitForEvent
    // has been called and has processed the initial
    // debug events.  We need to wait for activation
    // before we query information about the session
    // as not all information is available until the
    // session is fully active.  We could put these
    // queries into CreateProcess as that happens
    // early and when the session is fully active, but
    // for example purposes we'll wait for an
    // active SessionStatus callback.
    // In non-callback applications this work can just
    // be done after the first successful WaitForEvent.
    if (SessionStatus != DEBUG_SESSION_ACTIVE)
    {
        return S_OK;
    }

    HRESULT Status;

    //
    // Find the register index for eax as we'll need
    // to access eax.
    //

    if ((Status = g_Registers->GetIndexByName("eax", &g_EaxIndex)) != S_OK)
    {
        Exit(1, "GetIndexByName failed, 0x%X\n", Status);
    }

    if ((Status = g_Registers->GetIndexByName("eip", &g_EipIndex)) != S_OK)
    {
        Exit(1, "GetIndexByName failed, 0x%X\n", Status);
    }

    return S_OK;
}

EventCallbacks g_EventCb;

//----------------------------------------------------------------------------
//
// Initialization and main event loop.
//
//----------------------------------------------------------------------------

void CreateInterfaces(void)
{
    SYSTEM_INFO SysInfo;

    // For purposes of keeping this example simple the
    // code only works on x86 machines.  There's no reason
    // that it couldn't be made to work on all processors, though.
    GetSystemInfo(&SysInfo);
    if (SysInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL)
    {
        Exit(1, "This program only runs on x86 machines.\n");
    }

    // Get default version information.
    g_OsVer.dwOSVersionInfoSize = sizeof(g_OsVer);
    if (!GetVersionEx(&g_OsVer))
    {
        Exit(1, "GetVersionEx failed, %d\n", (long)GetLastError());
    }

    HRESULT Status;

    // Start things off by getting an initial interface from
    // the engine.  This can be any engine interface but is
    // generally IDebugClient as the client interface is
    // where sessions are started.
    if ((Status = DebugCreate(__uuidof(IDebugClient),
                              (void **)&g_Client)) != S_OK)
    {
        Exit(1, "DebugCreate failed, 0x%X\n", Status);
    }

    // Query for some other interfaces that we'll need.
    if ((Status = g_Client->QueryInterface(__uuidof(IDebugControl),
                                           (void **)&g_Control)) != S_OK ||
        (Status = g_Client->QueryInterface(__uuidof(IDebugDataSpaces),
                                           (void **)&g_Data)) != S_OK ||
        (Status = g_Client->QueryInterface(__uuidof(IDebugRegisters),
                                           (void **)&g_Registers)) != S_OK ||
        (Status = g_Client->QueryInterface(__uuidof(IDebugSymbols),
                                           (void **)&g_Symbols)) != S_OK)
    {
        Exit(1, "QueryInterface failed, 0x%X\n", Status);
    }
}

void handle_event_loop(void)
{
    HRESULT Status;
    ULONG ExecStatus;

    for (;;)
    {
        if ((Status = g_Control->WaitForEvent(DEBUG_WAIT_DEFAULT,
                                              INFINITE)) != S_OK)
        {

            // Check and see whether the session is running or not.
            if (g_Control->GetExecutionStatus(&ExecStatus) == S_OK &&
                ExecStatus == DEBUG_STATUS_NO_DEBUGGEE)
            {
                // The session ended so we can quit.
                break;
            }

            // There was a real error.
            Exit(1, "WaitForEvent failed, 0x%X\n", Status);
        }

        g_Control->GetExecutionStatus(&ExecStatus);
        if (ExecStatus == DEBUG_STATUS_NO_DEBUGGEE)
        {
            break;
        }

        // User chose to ignore so restart things.
        if ((Status = g_Control->SetExecutionStatus(DEBUG_STATUS_GO_HANDLED)) != S_OK)
        {
            Exit(1, "SetExecutionStatus failed, 0x%X\n", Status);
        }
    }
}

void init_debug_callback()
{
    CreateInterfaces();

    HRESULT Status;

    if (g_SymbolPath != NULL)
    {
        if ((Status = g_Symbols->SetSymbolPath(g_SymbolPath)) != S_OK)
        {
            Exit(1, "SetSymbolPath failed, 0x%X\n", Status);
        }
    }

    // Register our event callbacks.
    if ((Status = g_Client->SetEventCallbacks(&g_EventCb)) != S_OK)
    {
        Exit(1, "SetEventCallbacks failed, 0x%X\n", Status);
    }

    /*
		if ((Status = g_Client->SetOutputCallbacks(&g_OutputCb)) != S_OK)
	{
		Exit(1, "SetOutputCallbacks failed, 0x%X\n", Status);
	}
	*/
}

void exec_testcase(void)
{
    HRESULT Status;

    is_crash = 0;

    // init_debug_callback();

    if (isFuzzMode)
    {
        g_debug_output_fp = fopen("debug-output.txt", "w");
    }
    else
    {
        g_debug_output_fp = stdout;
    }

    if ((Status = g_Client->CreateProcess(0, g_CommandLine,
                                          DEBUG_ONLY_THIS_PROCESS)) != S_OK)
    {
        Exit(1, "CreateProcess failed, 0x%X\n", Status);
    }

    handle_event_loop();

    save_status();
    save_all_trace();

    // GetModuleList(dwDebugeePid);

    g_Client->TerminateProcesses();
    g_Client->DetachProcesses();
    g_Client->EndSession(DEBUG_END_PASSIVE);

    // KillProcess(dwDebugeePid);
    // clean_resource();

    if (isFuzzMode)
    {
        fclose(g_debug_output_fp);
    }

    if (patch_to_binary)
    {
        int patch_instr_count = patch_to_binary_file();
        printf("patch %d basic block\n", patch_instr_count);
    }

    reset_cmi_info();
}

void load_bb_info(char *fpath)
{
    COV_MOD_INFO *cmi = new COV_MOD_INFO;

    if (!isFuzzMode)
    {
        printf("[load_bb_info] load %s!\n", fpath);
    }

    FILE *fp = fopen(fpath, "rb");

    if (fp == NULL)
    {
        printf("[load_bb_info] open %s failed!\n", fpath);
        exit(0);
    }

    fread(&cmi->rva_size, 4, 1, fp);

    int fname_sz = 0;
    fread(&fname_sz, 4, 1, fp);
    fread(cmi->module_name, fname_sz, 1, fp);

    BB_INFO tmp = {0};
    while (fread(&tmp, 4 * 3, 1, fp) == 1)
    {
        fread(&tmp.instr, tmp.instr_size, 1, fp);
        BB_INFO *info = (BB_INFO *)malloc(sizeof(BB_INFO));
        memcpy(info, &tmp, sizeof(BB_INFO));
        cmi->bb_info_map[info->voff] = info;
        //printf("voff:0x%X\n", info->voff);
    }
    fclose(fp);

    cmi->image_base = 0;
    cmi->image_end = 0;
    cmi->full_path[0] = '\x00';
    cmi->mod_id = g_cov_mod_count++;

    cov_mod_info_list.push_back(cmi);
}

#include <fstream>
#include <iostream>
using namespace std;
using json = nlohmann::json;

void parse_json(char *path)
{

    // read a JSON file
    std::ifstream fs(path);
    json j;
    fs >> j;

    std::string exit_basci_block_list = j["exit_basci_block_list"];
    std::vector<std::string> basic_block_file_list = j["basic_block_file_path"];
    std::vector<std::string> args = j["args"];

    patch_to_binary = j["patch_to_binary"];

    if (j.contains("is_fuzz_mode"))
    {
        isFuzzMode = j["is_fuzz_mode"];
    }

    if (j.contains("server_sock_port"))
    {
        server_sock_port = j["server_sock_port"];
    }

    if (j.contains("pre_command"))
    {
        std::string pre_cmd = j["pre_command"];
        strcpy(g_pre_command, pre_cmd.c_str());
    }

    if (j.contains("wait_for_dll"))
    {
        std::string wait_for_dll = j["wait_for_dll"];
        strcpy(g_wait_for_dll, wait_for_dll.c_str());
    }

    for (size_t i = 0; i < basic_block_file_list.size(); i++)
    {
        load_bb_info((char *)basic_block_file_list[i].c_str());
    }

    for (size_t i = 0; i < args.size(); i++)
    {
        strcat(g_CommandLine, args[i].c_str());
        strcat(g_CommandLine, " ");
    }

    char *ptr, *retptr;
    int i = 0;

    ptr = strdup(exit_basci_block_list.c_str());

    unsigned int exit_bb = 0;

    while ((retptr = strtok(ptr, ",")) != NULL)
    {
        // printf("substr[%d]:%s\n", i++, retptr);
        ptr = NULL;
        sscanf(retptr, "%x", &exit_bb);

        if (exit_bb != 0)
        {
            exit_bb_list[exit_bb] = 1;
        }
    }

    printf("isFuzzMode: %d\n", isFuzzMode);
    printf("parse_json: %s\n", path);
}

void __cdecl main(int Argc, char **Argv)
{
    isFuzzMode = 0;

    if (Argc == 2)
    {
        parse_json(Argv[1]);
    }
    else
    {
        parse_json("config.json");
    }

    if (isFuzzMode)
    {
        init_tcp_client();
    }

    int iResult;

    char sendbuf[0x100] = {0};
    char recvbuf[0x100] = {0};

    init_debug_callback();

    for (;;)
    {

        if (isFuzzMode)
        {

            *(unsigned int *)sendbuf = 0x1122ddaa;
            iResult = send(ConnectSocket, sendbuf, 4, 0);

            if (iResult == -1)
            {
                puts("send start packet failed!");
                break;
            }

            iResult = recv(ConnectSocket, recvbuf, 4, 0);

            if (iResult == -1)
            {
                puts("recv from tracer failed!");
                break;
            }
        }

        exec_testcase();

        if (!isFuzzMode)
        {
            break;
        }

        if (isFuzzMode)
        {

            *(unsigned int *)sendbuf = 0x33333333;
            iResult = send(ConnectSocket, sendbuf, 4, 0);
            if (iResult == -1)
            {
                puts("send finish packet failed!");
                break;
            }
        }
    }

    clean_resource();

    Exit(0, "");
}
