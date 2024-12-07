#include "injector.h"
#include <Windows.h>
#include <TlHelp32.h>

bool hijack_thread(HANDLE process_handle, void* function, void* argument, PDWORD_PTR ret) {
    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot_handle == INVALID_HANDLE_VALUE)
        return false;

    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(THREADENTRY32);
    BOOL result = Thread32First(snapshot_handle, &thread_entry);
    bool found = false;

    DWORD process_id = GetProcessId(process_handle);

    while (result) {
        if (thread_entry.th32OwnerProcessID == process_id) {
            found = true;

            break;
        }

        result = Thread32Next(snapshot_handle, &thread_entry);
    }

    CloseHandle(snapshot_handle);

    if (!found)
        return false;

    HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_entry.th32ThreadID);

    if (thread_handle == nullptr)
        return false;

    SuspendThread(thread_handle);

    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL;

    if (!GetThreadContext(thread_handle, &context)) {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);

        return false;
    }

#ifdef _WIN64
    unsigned char data_and_instructions_buffer[] = {
        0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xEC, 0x08,
        0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
        0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x50,
        0x51,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xEC, 0x10,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x10,
        0x48, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x59,
        0x58,
        0xC6, 0x05, 0xB1, 0xFF, 0xFF, 0xFF, 0x01,
        0xC3
    };
#else
    unsigned char data_and_instructions_buffer[] = {
        0x00,
        0x00, 0x00, 0x00, 0x00,
        0x83, 0xEC, 0x04,
        0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
        0x50,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0,
        0xA3, 0x00, 0x00, 0x00, 0x00,
        0x58,
        0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xC3
    };
#endif

    LPVOID data_and_instructions_buffer2 = VirtualAllocEx(process_handle, nullptr, sizeof(data_and_instructions_buffer), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (data_and_instructions_buffer2 == nullptr) {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);

        return false;
    }

#ifdef _WIN64
    *(PDWORD)(data_and_instructions_buffer + 16) = context.Rip & 0xFFFFFFFF;
    *(PDWORD)(data_and_instructions_buffer + 24) = (context.Rip >> 32) & 0xFFFFFFFF;
    *(void**)(data_and_instructions_buffer + 32) = function;
    *(void**)(data_and_instructions_buffer + 42) = argument;
    *(void**)(data_and_instructions_buffer + 62) = (void*)((DWORD_PTR)data_and_instructions_buffer2 + 1);
#else
    *(PDWORD)(data_and_instructions_buffer + 11) = context.Eip;
    *(void**)(data_and_instructions_buffer + 17) = function;
    *(void**)(data_and_instructions_buffer + 22) = argument;
    *(void**)(data_and_instructions_buffer + 29) = (void*)((DWORD_PTR)data_and_instructions_buffer2 + 1);
    *(void**)(data_and_instructions_buffer + 36) = data_and_instructions_buffer2;
#endif

    WriteProcessMemory(process_handle, data_and_instructions_buffer2, data_and_instructions_buffer, sizeof(data_and_instructions_buffer), nullptr);

#ifdef _WIN64
    context.Rip = (DWORD64)data_and_instructions_buffer2 + 9;
#else
    context.Eip = (DWORD)data_and_instructions_buffer2 + 5;
#endif

    if (!SetThreadContext(thread_handle, &context)) {
        VirtualFreeEx(process_handle, data_and_instructions_buffer2, 0, MEM_RELEASE);
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);

        return false;
    }

    ResumeThread(thread_handle);
    CloseHandle(thread_handle);

    bool returned = false;

    while (!returned)
        ReadProcessMemory(process_handle, data_and_instructions_buffer2, &returned, sizeof(bool), nullptr);

    ReadProcessMemory(process_handle, (void*)((DWORD_PTR)data_and_instructions_buffer2 + 1), ret, sizeof(DWORD_PTR), nullptr);

    VirtualFreeEx(process_handle, data_and_instructions_buffer2, 0, MEM_RELEASE);

    return true;
}

struct ShellcodeData {
    LPVOID image_buffer;
    HMODULE (WINAPI *LoadLibraryA)(LPCSTR lpLibFileName);
    FARPROC (WINAPI *GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
    DWORD (WINAPI *TlsAlloc)(VOID);
    BOOL (WINAPI *TlsFree)(DWORD dwTlsIndex);
    LPVOID (WINAPI *VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    BOOL (WINAPI *VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
#ifdef _WIN64
    BOOLEAN (__cdecl *RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif
};

BOOL __stdcall Shellcode(ShellcodeData* shellcode_data) {
    PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)shellcode_data->image_buffer;
    PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_dos_header + image_dos_header->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR image_import_descriptor = (image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) ? (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)shellcode_data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) : nullptr;
    HMODULE library_handle;
    PIMAGE_THUNK_DATA image_thunk_data1, image_thunk_data2;
    FARPROC function;

    if (image_import_descriptor != nullptr) {
        while (image_import_descriptor->Name != 0) {
            library_handle = shellcode_data->LoadLibraryA((LPCSTR)((DWORD_PTR)shellcode_data->image_buffer + image_import_descriptor->Name));

            if (library_handle == nullptr)
                continue;

            image_thunk_data1 = (PIMAGE_THUNK_DATA)((DWORD_PTR)shellcode_data->image_buffer + image_import_descriptor->OriginalFirstThunk);
            image_thunk_data2 = (PIMAGE_THUNK_DATA)((DWORD_PTR)shellcode_data->image_buffer + image_import_descriptor->FirstThunk);

            while (image_thunk_data1->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(image_thunk_data1->u1.Ordinal) != 0)
                    function = shellcode_data->GetProcAddress(library_handle, MAKEINTRESOURCE(image_thunk_data1->u1.Ordinal));
                else
                    function = shellcode_data->GetProcAddress(library_handle, (const char*)((PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)shellcode_data->image_buffer + image_thunk_data1->u1.AddressOfData))->Name);

                if (function == nullptr)
                    continue;

                image_thunk_data2->u1.Function = (DWORD_PTR)function;

                ++image_thunk_data1;
                ++image_thunk_data2;
            }

            ++image_import_descriptor;
        }
    }

    PIMAGE_DELAYLOAD_DESCRIPTOR image_delay_load_descriptor = (image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0) ? (PIMAGE_DELAYLOAD_DESCRIPTOR)((DWORD_PTR)shellcode_data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress) : nullptr;

    if (image_delay_load_descriptor != nullptr) {
        while (image_delay_load_descriptor->DllNameRVA != 0) {
            library_handle = shellcode_data->LoadLibraryA((LPCSTR)((DWORD_PTR)shellcode_data->image_buffer + image_delay_load_descriptor->DllNameRVA));

            if (library_handle == nullptr)
                continue;

            image_thunk_data1 = (PIMAGE_THUNK_DATA)((DWORD_PTR)shellcode_data->image_buffer + image_delay_load_descriptor->ImportNameTableRVA);
            image_thunk_data2 = (PIMAGE_THUNK_DATA)((DWORD_PTR)shellcode_data->image_buffer + image_delay_load_descriptor->ImportAddressTableRVA);

            while (image_thunk_data1->u1.AddressOfData != 0) {
                if (IMAGE_SNAP_BY_ORDINAL(image_thunk_data1->u1.Ordinal) != 0)
                    function = shellcode_data->GetProcAddress(library_handle, MAKEINTRESOURCE(image_thunk_data1->u1.Ordinal));
                else
                    function = shellcode_data->GetProcAddress(library_handle, (const char*)((PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)shellcode_data->image_buffer + image_thunk_data1->u1.AddressOfData))->Name);

                if (function == nullptr)
                    continue;

                image_thunk_data2->u1.Function = (DWORD_PTR)function;

                ++image_thunk_data1;
                ++image_thunk_data2;
            }

            ++image_delay_load_descriptor;
        }
    }

    PIMAGE_BASE_RELOCATION image_base_relocation = (image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) ? (PIMAGE_BASE_RELOCATION)((DWORD_PTR)shellcode_data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) : nullptr;
    DWORD_PTR delta = (DWORD_PTR)shellcode_data->image_buffer - image_nt_headers->OptionalHeader.ImageBase;

    if (image_base_relocation != nullptr && delta != 0) {
        SIZE_T count;
        PWORD entries;
        DWORD offset;

        while (image_base_relocation->VirtualAddress != 0) {
            count = (image_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            entries = (PWORD)(image_base_relocation + 1);

            for (DWORD_PTR i = 0; i < count; ++i) {
                offset = image_base_relocation->VirtualAddress + (entries[i] & 0xFFF);

                switch (entries[i] >> 12) {
#ifdef _WIN64
                case IMAGE_REL_BASED_DIR64:
#else
                case IMAGE_REL_BASED_HIGHLOW:
#endif
                    *(PDWORD_PTR)((DWORD_PTR)shellcode_data->image_buffer + offset) += delta;
                    break;
                }
            }

            image_base_relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)image_base_relocation + image_base_relocation->SizeOfBlock);
        }
    }

    PIMAGE_TLS_DIRECTORY image_tls_directory = (image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0) ? (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)shellcode_data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) : nullptr;

    if (image_tls_directory != nullptr) {
        DWORD tls_index = shellcode_data->TlsAlloc();

        if (tls_index != TLS_OUT_OF_INDEXES) {
            DWORD_PTR tls_size = image_tls_directory->EndAddressOfRawData - image_tls_directory->StartAddressOfRawData;
            LPVOID tls_data = shellcode_data->VirtualAlloc(nullptr, tls_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (tls_data == nullptr)
                shellcode_data->TlsFree(tls_index);
            else {
                for (DWORD_PTR i = 0; i < tls_size; ++i)
                    *(unsigned char*)((DWORD_PTR)tls_data + i) = *(unsigned char*)((DWORD_PTR)image_tls_directory->StartAddressOfRawData + i);

                void** ThreadLocalStoragePointer =
#ifdef _WIN64
                    *(void***)((DWORD_PTR)__readgsqword(0x30) + 0x58);
#else
                    *(void***)((DWORD_PTR)__readfsdword(0x18) + 0x2C);
#endif

                if (ThreadLocalStoragePointer == nullptr) {
                    shellcode_data->VirtualFree(tls_data, 0, MEM_RELEASE);
                    shellcode_data->TlsFree(tls_index);
                } else {
                    *(DWORD_PTR*)image_tls_directory->AddressOfIndex = tls_index;
                    ThreadLocalStoragePointer[tls_index] = tls_data;
                }
            }
        }

        if (image_tls_directory->AddressOfCallBacks != 0) {
            PIMAGE_TLS_CALLBACK* image_tls_callbacks = (PIMAGE_TLS_CALLBACK*)image_tls_directory->AddressOfCallBacks;

            for (; *image_tls_callbacks; ++image_tls_callbacks)
                (*image_tls_callbacks)(shellcode_data->image_buffer, DLL_PROCESS_ATTACH, nullptr);
        }
    }

#ifdef _WIN64
    if (image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0)
        shellcode_data->RtlAddFunctionTable((PRUNTIME_FUNCTION)((DWORD_PTR)shellcode_data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress), image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION), (DWORD64)shellcode_data->image_buffer);
#endif

    if (image_nt_headers->OptionalHeader.AddressOfEntryPoint != 0)
        return ((BOOL (WINAPI *)(HINSTANCE, DWORD, LPVOID))((DWORD_PTR)shellcode_data->image_buffer + image_nt_headers->OptionalHeader.AddressOfEntryPoint))((HMODULE)shellcode_data->image_buffer, DLL_PROCESS_ATTACH, nullptr);

    return FALSE;
}

bool inject_dll(const int process_id, const char* dll_path) {
    HANDLE file_handle = CreateFile(dll_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (file_handle == INVALID_HANDLE_VALUE)
        return false;

    DWORD file_size = GetFileSize(file_handle, nullptr);

    if (file_size == INVALID_FILE_SIZE) {
        CloseHandle(file_handle);

        return false;
    }

    LPVOID file_buffer = VirtualAlloc(nullptr, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (file_buffer == nullptr) {
        CloseHandle(file_handle);

        return false;
    }

    if (!ReadFile(file_handle, file_buffer, file_size, nullptr, nullptr)) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);
        CloseHandle(file_handle);

        return false;
    }

    CloseHandle(file_handle);

    PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)file_buffer;

    if (image_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_dos_header + image_dos_header->e_lfanew);

    if (image_nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    if ((image_nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

#ifdef _WIN64
    if (image_nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }
#else
    if (image_nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }
#endif

    HANDLE token_handle;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token_handle)) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    TOKEN_PRIVILEGES token_privileges;

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &token_privileges.Privileges[0].Luid)) {
        CloseHandle(token_handle);
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token_handle, FALSE, &token_privileges, 0, nullptr, nullptr)) {
        CloseHandle(token_handle);
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    CloseHandle(token_handle);

    HANDLE process_handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, process_id);

    if (process_handle == nullptr) {
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    LPVOID image_buffer = VirtualAllocEx(process_handle, nullptr, image_nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (image_buffer == nullptr) {
        CloseHandle(process_handle);
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    WriteProcessMemory(process_handle, image_buffer, file_buffer, image_nt_headers->OptionalHeader.SizeOfHeaders, nullptr);

    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(image_nt_headers);

    for (WORD i = 0; i < image_nt_headers->FileHeader.NumberOfSections; ++i) {
        if (section_header[i].SizeOfRawData == 0)
            continue;

        WriteProcessMemory(process_handle, (LPVOID)((DWORD_PTR)image_buffer + section_header[i].VirtualAddress), (LPCVOID)((DWORD_PTR)file_buffer + section_header[i].PointerToRawData), section_header[i].SizeOfRawData, nullptr);
    }

    ShellcodeData shellcode_data;
    shellcode_data.image_buffer = image_buffer;
    shellcode_data.LoadLibraryA = LoadLibraryA;
    shellcode_data.GetProcAddress = GetProcAddress;
    shellcode_data.TlsAlloc = TlsAlloc;
    shellcode_data.TlsFree = TlsFree;
    shellcode_data.VirtualAlloc = VirtualAlloc;
    shellcode_data.VirtualFree = VirtualFree;
#ifdef _WIN64
    shellcode_data.RtlAddFunctionTable = RtlAddFunctionTable;
#endif

    LPVOID shellcode_data_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(shellcode_data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (shellcode_data_buffer == nullptr) {
        VirtualFreeEx(process_handle, image_buffer, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    WriteProcessMemory(process_handle, shellcode_data_buffer, &shellcode_data, sizeof(shellcode_data), nullptr);

    LPVOID shellcode_buffer = VirtualAllocEx(process_handle, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (shellcode_buffer == nullptr) {
        VirtualFreeEx(process_handle, shellcode_data_buffer, 0, MEM_RELEASE);
        VirtualFreeEx(process_handle, image_buffer, 0, MEM_RELEASE);
        CloseHandle(process_handle);
        VirtualFree(file_buffer, 0, MEM_RELEASE);

        return false;
    }

    WriteProcessMemory(process_handle, shellcode_buffer, (LPCVOID)Shellcode, 4096, nullptr);

    BOOL ret = FALSE;

    if (!hijack_thread(process_handle, shellcode_buffer, shellcode_data_buffer, (PDWORD_PTR)&ret)) {
        HANDLE remote_thread_handle = CreateRemoteThread(process_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_buffer, shellcode_data_buffer, 0, nullptr);

        if (remote_thread_handle == nullptr) {
            VirtualFreeEx(process_handle, shellcode_buffer, 0, MEM_RELEASE);
            VirtualFreeEx(process_handle, shellcode_data_buffer, 0, MEM_RELEASE);
            VirtualFreeEx(process_handle, image_buffer, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            VirtualFree(file_buffer, 0, MEM_RELEASE);

            return false;
        }

        WaitForSingleObject(remote_thread_handle, INFINITE);
        GetExitCodeThread(remote_thread_handle, (LPDWORD)&ret);

        CloseHandle(remote_thread_handle);
    }

    VirtualFreeEx(process_handle, shellcode_buffer, 0, MEM_RELEASE);
    VirtualFreeEx(process_handle, shellcode_data_buffer, 0, MEM_RELEASE);

    if (!ret)
        VirtualFreeEx(process_handle, image_buffer, 0, MEM_RELEASE);
    else {
        unsigned char* null_buffer = new unsigned char[image_nt_headers->OptionalHeader.SizeOfHeaders]();

        WriteProcessMemory(process_handle, image_buffer, null_buffer, image_nt_headers->OptionalHeader.SizeOfHeaders, nullptr);

        delete[] null_buffer;

        for (WORD i = 0; i < image_nt_headers->FileHeader.NumberOfSections; ++i) {
            if (section_header[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
                if (section_header[i].SizeOfRawData == 0)
                    continue;

                null_buffer = new unsigned char[section_header[i].SizeOfRawData]();

                // ???
                WriteProcessMemory(process_handle, (LPVOID)((DWORD_PTR)image_buffer + section_header[i].VirtualAddress), null_buffer, section_header[i].SizeOfRawData, nullptr);

                delete[] null_buffer;
            } else {
                DWORD new_protect = PAGE_NOACCESS;

                if ((section_header[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE))
                    new_protect = PAGE_EXECUTE_READWRITE;
                else if ((section_header[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ))
                    new_protect = PAGE_EXECUTE_READ;
                else if ((section_header[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) == (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE))
                    new_protect = PAGE_EXECUTE_WRITECOPY;
                else if ((section_header[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)) == (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE))
                    new_protect = PAGE_READWRITE;
                else if (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    new_protect = PAGE_EXECUTE;
                else if (section_header[i].Characteristics & IMAGE_SCN_MEM_READ)
                    new_protect = PAGE_READONLY;
                else if (section_header[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                    new_protect = PAGE_WRITECOPY;

                DWORD old_protect;
                VirtualProtectEx(process_handle, (LPVOID)((DWORD_PTR)image_buffer + section_header[i].VirtualAddress), section_header[i].Misc.VirtualSize, new_protect, &old_protect);
            }
        }
    }

    CloseHandle(process_handle);
    VirtualFree(file_buffer, 0, MEM_RELEASE);

    return true;
}
