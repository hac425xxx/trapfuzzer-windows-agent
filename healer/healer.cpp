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
#include <windows.h>
#include <dbgeng.h>

#include <map> 
#include <vector>

typedef struct _BB_INFO {
	unsigned int voff;
	unsigned int foff;
	unsigned int instr_size;
	unsigned char instr[4];
}BB_INFO;


typedef unsigned int PC_SIZE;

typedef struct _COV_MOD_INFO {
	std::map<unsigned int, BB_INFO*> bb_info_map;
	char module_name[1024];
	char full_path[0x200];
	ULONG64 image_base;
	ULONG64 image_end;
	unsigned int rva_size;
	unsigned int mod_id;
	std::vector<unsigned int> bb_trace;
}COV_MOD_INFO;


std::vector<COV_MOD_INFO*> cov_mod_info_list;
unsigned int g_cov_mod_count = 0;



PCSTR g_SymbolPath;
char g_CommandLine[8 * MAX_PATH];
BOOL g_Verbose;
BOOL g_NeedVersionBps;

IDebugClient* g_Client;
IDebugControl* g_Control;
IDebugDataSpaces* g_Data;
IDebugRegisters* g_Registers;
IDebugSymbols* g_Symbols;

struct BREAKPOINT
{
    IDebugBreakpoint* Bp;
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





COV_MOD_INFO * get_cov_mod_info_by_pc(unsigned int pc)
{
	COV_MOD_INFO * ret = NULL;
	for (int i = 0; i < cov_mod_info_list.size(); i++)
	{
		COV_MOD_INFO* cmi = cov_mod_info_list[i];
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



COV_MOD_INFO * get_cov_mod_info_by_module_name(char* mod_name)
{
	COV_MOD_INFO * ret = NULL;
	for (int i = 0; i < cov_mod_info_list.size(); i++)
	{
		COV_MOD_INFO* cmi = cov_mod_info_list[i];
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


COV_MOD_INFO * reset_cmi_info()
{
	COV_MOD_INFO * ret = NULL;
	for (int i = 0; i < cov_mod_info_list.size(); i++)
	{
		COV_MOD_INFO* cmi = cov_mod_info_list[i];
		cmi->bb_trace.clear();
		cmi->image_base = 0;
		cmi->image_end = 0;
		cmi->full_path[0] = '\0';
	}

	return ret;
}


void save_all_trace()
{

	COV_MOD_INFO * ret = NULL;
	for (int i = 0; i < cov_mod_info_list.size(); i++)
	{
		COV_MOD_INFO* cmi = cov_mod_info_list[i];

		char bb_file_name[0x100] = { 0 };
		sprintf(bb_file_name, "%s.trace", cmi->module_name);

		FILE *pfile = fopen(bb_file_name, "w");//以写的方式打开C.txt文件。   

		for (size_t i = 0; i < cmi->bb_trace.size(); i++)
		{
			fprintf(pfile, "%p\n", cmi->bb_trace[i]);
		}

		fflush(pfile);//刷新缓冲区。将缓冲区数据写入文件   
		fclose(pfile);//关闭文件  
	}
}


ULONG64 g_TraceFrom[3];



//----------------------------------------------------------------------------
//
// Utility routines.
//
//----------------------------------------------------------------------------


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

void
Exit(int Code, _In_ _Printf_format_string_ PCSTR Format, ...)
{

	clean_resource();
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

void
Print(_In_ _Printf_format_string_ PCSTR Format, ...)
{
    va_list Args;

    printf("HEALER: ");
    va_start(Args, Format);
    vprintf(Format, Args);
    va_end(Args);
}

void
dump_stack_trace(void)
{
	HRESULT Status;
	PDEBUG_STACK_FRAME Frames = NULL;
	int Count = 50;

	printf("\nFirst %d frames of the call stack:\n", Count);

	
	ULONG Filled;

	Frames = new DEBUG_STACK_FRAME[Count];
	if (Frames == NULL)
	{
		Exit(1, "Unable to allocate stack frames\n");
	}

	if ((Status = g_Control->
		GetStackTrace(0, 0, 0, Frames, Count, &Filled)) != S_OK)
	{
		Exit(1, "GetStackTrace failed, 0x%X\n", Status);
	}

	

	Count = Filled;

	ULONG index;
	ULONG64 base;

	FILE *pfile = fopen("stacktrace.txt", "w");//以写的方式打开C.txt文件。   

	for (size_t i = 0; i < Count; i++)
	{
		printf("InstructionOffset: %p ", Frames[i].InstructionOffset);
		printf("ReturnOffset: %p\n", Frames[i].ReturnOffset);

		g_Symbols->GetModuleByOffset(Frames[i].InstructionOffset, 0, &index, &base);

		fprintf(pfile, "%p\n", Frames[i].InstructionOffset);
	}

	fflush(pfile);//刷新缓冲区。将缓冲区数据写入文件   
	fclose(pfile);//关闭文件  


	delete[] Frames;
}


//----------------------------------------------------------------------------
//
// Healing routines.
//
//----------------------------------------------------------------------------

char* getFileNameFromPath(char* path, char separator)
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

void add_module_loaded_info(char* fpath, ULONG64 base)
{
	char* fname = getFileNameFromPath(fpath, '\\');
	COV_MOD_INFO* cmi = get_cov_mod_info_by_module_name(fname);
	if (cmi != NULL)
	{
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
    STDMETHOD_(ULONG, AddRef)(
        THIS
        );
    STDMETHOD_(ULONG, Release)(
        THIS
        );

    // IDebugEventCallbacks.
    STDMETHOD(GetInterestMask)(
        THIS_
        _Out_ PULONG Mask
        );
    
    STDMETHOD(Breakpoint)(
        THIS_
        _In_ PDEBUG_BREAKPOINT Bp
        );
    STDMETHOD(Exception)(
        THIS_
        _In_ PEXCEPTION_RECORD64 Exception,
        _In_ ULONG FirstChance
        );
    STDMETHOD(CreateProcess)(
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
        _In_ ULONG64 StartOffset
        );
    STDMETHOD(LoadModule)(
        THIS_
        _In_ ULONG64 ImageFileHandle,
        _In_ ULONG64 BaseOffset,
        _In_ ULONG ModuleSize,
        _In_ PCSTR ModuleName,
        _In_ PCSTR ImageName,
        _In_ ULONG CheckSum,
        _In_ ULONG TimeDateStamp
        );
    STDMETHOD(SessionStatus)(
        THIS_
        _In_ ULONG Status
        );
};

STDMETHODIMP_(ULONG)
EventCallbacks::AddRef(
    THIS
    )
{
    // This class is designed to be static so
    // there's no true refcount.
    return 1;
}

STDMETHODIMP_(ULONG)
EventCallbacks::Release(
    THIS
    )
{
    // This class is designed to be static so
    // there's no true refcount.
    return 0;
}

STDMETHODIMP
EventCallbacks::GetInterestMask(
    THIS_
    _Out_ PULONG Mask
    )
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
    _In_ PDEBUG_BREAKPOINT Bp
    )
{
   
    return DEBUG_STATUS_NO_CHANGE;
   
}

STDMETHODIMP
EventCallbacks::Exception(
    THIS_
    _In_ PEXCEPTION_RECORD64 Exception,
    _In_ ULONG FirstChance
    )
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
		
		COV_MOD_INFO * cmi = get_cov_mod_info_by_pc(Exception->ExceptionAddress);
		if (cmi != NULL)
		{
			
			BB_INFO* bi = cmi->bb_info_map[Exception->ExceptionAddress - cmi->image_base];

			printf("rva: 0x%lx\n", bi->voff);

			cmi->bb_trace.push_back(bi->voff);

			if (g_Data->WriteVirtual(Exception->ExceptionAddress, bi->instr,
				bi->instr_size, &Done) != S_OK ||
				Done != bi->instr_size)
			{
				return DEBUG_STATUS_NO_CHANGE;
			}
		}
		return DEBUG_STATUS_GO;
	}

	if (Exception->ExceptionCode == STATUS_ACCESS_VIOLATION) {
		dump_stack_trace();
		save_all_trace();
		//g_Client->TerminateProcesses();
		//g_Client->EndSession(DEBUG_END_ACTIVE_TERMINATE);
		g_Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, "q", DEBUG_EXECUTE_ECHO);
		return DEBUG_STATUS_NO_DEBUGGEE;
	}
  
    
    return DEBUG_STATUS_GO_HANDLED;
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
    _In_ ULONG64 StartOffset
    )
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
    
	// This would be where any executable image patching would go.
	Print("Executable '%s' loaded at %I64x\n", ImageName, BaseOffset);

	add_module_loaded_info((char*)ImageName, BaseOffset);
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
    _In_ ULONG TimeDateStamp
    )
{
    UNREFERENCED_PARAMETER(ImageFileHandle);
    UNREFERENCED_PARAMETER(ModuleSize);
    UNREFERENCED_PARAMETER(ModuleName);
    UNREFERENCED_PARAMETER(CheckSum);
    UNREFERENCED_PARAMETER(TimeDateStamp);

	// Any DLL-specific image patching goes here.
	Print("DLL '%s' loaded at %I64x\n", ImageName, BaseOffset);
	add_module_loaded_info((char*)ImageName, BaseOffset);
    return DEBUG_STATUS_GO;
}

STDMETHODIMP
EventCallbacks::SessionStatus(
    THIS_
    _In_ ULONG SessionStatus
    )
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

void
CreateInterfaces(void)
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
                              (void**)&g_Client)) != S_OK)
    {
        Exit(1, "DebugCreate failed, 0x%X\n", Status);
    }

    // Query for some other interfaces that we'll need.
    if ((Status = g_Client->QueryInterface(__uuidof(IDebugControl),
                                           (void**)&g_Control)) != S_OK ||
        (Status = g_Client->QueryInterface(__uuidof(IDebugDataSpaces),
                                           (void**)&g_Data)) != S_OK ||
        (Status = g_Client->QueryInterface(__uuidof(IDebugRegisters),
                                           (void**)&g_Registers)) != S_OK ||
        (Status = g_Client->QueryInterface(__uuidof(IDebugSymbols),
                                           (void**)&g_Symbols)) != S_OK)
    {
        Exit(1, "QueryInterface failed, 0x%X\n", Status);
    }

}

void
ParseCommandLine(int Argc, _In_reads_(Argc) PCSTR* Argv)
{
    while (--Argc > 0)
    {
        Argv++;

        if (!strcmp(Argv[0], "-plat"))
        {
            Argv++;
            Argc--;
            if (Argc > 0)
            {
                if (EOF == sscanf_s(Argv[0], "%i", (long*)&g_OsVer.dwPlatformId))
                {
                    Exit(1, "-plat illegal argument type\n");
                }
                g_NeedVersionBps = TRUE;
            }
            else
            {
                Exit(1, "-plat missing argument\n");
            }
        }
        else if (!strcmp(Argv[0], "-v"))
        {
            g_Verbose = TRUE;
        }
        else if (!strcmp(Argv[0], "-ver"))
        {
            Argv++;
            Argc--;
            if (Argc > 0)
            {
                if (3 != sscanf_s(Argv[0], "%i.%i.%i",
                                    (long*)&g_OsVer.dwMajorVersion, (long*)&g_OsVer.dwMinorVersion,
                                    (long*)&g_OsVer.dwBuildNumber))
                {
                    Exit(1, "-ver illegal argument type\n");
                }
                g_NeedVersionBps = TRUE;
            }
            else
            {
                Exit(1, "-ver missing argument\n");
            }
        }
        else if (!strcmp(Argv[0], "-y"))
        {
            Argv++;
            Argc--;
            if (Argc > 0)
            {
                g_SymbolPath = Argv[0];
            }
            else
            {
                Exit(1, "-y missing argument\n");
            }
        }
        else
        {
            // Assume process arguments begin.
            break;
        }
    }
    
    //
    // Concatenate remaining arguments into a command line.
    //
    
    ULONG Pos = 0;
    while (Argc > 0)
    {
        BOOL Quote = FALSE;
        ULONG Len;
        
        // Quote arguments with spaces.
        if (strchr(Argv[0], ' ') != NULL || strchr(Argv[0], '\t') != NULL)
        {
            if (Pos < ARRAYSIZE(g_CommandLine))
            {
                g_CommandLine[Pos++] = '"';
            }
            else
            {
                Exit(1, "Command line too long\n");
            }
            Quote = TRUE;
        }

        Len = (ULONG)strlen(Argv[0]);
        if ((Len + Pos + 1) < ARRAYSIZE(g_CommandLine))
        {
            memcpy(&g_CommandLine[Pos], Argv[0], Len + 1);
        }
        else
        {
            Exit(1, "Command line too long\n");
        }
        
        Pos += Len;

        if (Quote)
        {
            if (Pos < ARRAYSIZE(g_CommandLine))
            {
                g_CommandLine[Pos++] = '"';
            }
            else
            {
                Exit(1, "Command line too long\n");
            }
        }

        if (Pos < ARRAYSIZE(g_CommandLine))
        {
            g_CommandLine[Pos++] = ' ';
        }
        else
        {
            Exit(1, "Command line too long\n");
        }
        
        Argv++;
        Argc--;
    }

    if (Pos < ARRAYSIZE(g_CommandLine))
    {
        g_CommandLine[Pos] = 0;
    }
    else
    {
        Exit(1, "Command line too long\n");
    }

    if (strlen(g_CommandLine) == 0)
    {
        Exit(1, "No application command line given\n");
    }
}


void
handle_event_loop(void)
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


		if (ExecStatus == DEBUG_STATUS_NO_DEBUGGEE) {
			break;
		}


		// User chose to ignore so restart things.
		if ((Status = g_Control->
			SetExecutionStatus(DEBUG_STATUS_GO_HANDLED)) != S_OK)
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
}

void
start_debug(void)
{
    HRESULT Status;
    
    // Everything's set up so start the app.
    if ((Status = g_Client->CreateProcess(0, g_CommandLine,
                                          DEBUG_ONLY_THIS_PROCESS)) != S_OK)
    {
        Exit(1, "CreateProcess failed, 0x%X\n", Status);
    }

	handle_event_loop();

	reset_cmi_info();

}





void load_bb_info(char* fpath)
{
	COV_MOD_INFO* cmi = new COV_MOD_INFO;

	FILE *fp = fopen(fpath, "rb");
	fread(&cmi->rva_size, 4, 1, fp);

	int fname_sz = 0;
	fread(&fname_sz, 4, 1, fp);
	fread(cmi->module_name, fname_sz, 1, fp);

	BB_INFO tmp = { 0 };
	while (fread(&tmp, 4 * 3, 1, fp) == 1)
	{
		fread(&tmp.instr, tmp.instr_size, 1, fp);
		BB_INFO* info = (BB_INFO*)malloc(sizeof(BB_INFO));
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



void __cdecl
main(int Argc, _In_reads_(Argc) PCSTR* Argv)
{

	load_bb_info("D:\\code\\windbg-ext-develop\\bin\\vuln.exe-bb.txt");

    
    
    ParseCommandLine(Argc, Argv);
	
	

	for (size_t i = 0; i < 3; i++)
	{
		init_debug_callback();
		start_debug();
		clean_resource();
	}

    Exit(0, "");
}
