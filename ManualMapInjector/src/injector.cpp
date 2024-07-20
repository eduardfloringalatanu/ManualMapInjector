#include "injector.h"
#include <Windows.h>
#include <TlHelp32.h>

int GetProcessID(const char* process_name) {
	HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot_handle == INVALID_HANDLE_VALUE)
		return -1;

	PROCESSENTRY32 process_entry; 
	process_entry.dwSize = sizeof(PROCESSENTRY32);
	BOOL result = Process32First(snapshot_handle, &process_entry);
	int process_id = -1;

	while (result) {
		if (!strcmp(process_name, process_entry.szExeFile)) {
			process_id = process_entry.th32ProcessID;
			
			break;
		}

		result = Process32Next(snapshot_handle, &process_entry);
	}

	CloseHandle(snapshot_handle);

	return process_id;
}

bool HijackThread(HANDLE process_handle, void* function, void* argument, PDWORD_PTR ret) {
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

	if (!thread_handle)
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
	unsigned char instructions_and_info_buffer[] = {
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
	unsigned char instructions_and_info_buffer[] = {
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

	LPVOID instructions_and_info_buffer2 = VirtualAllocEx(process_handle, nullptr, sizeof(instructions_and_info_buffer), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!instructions_and_info_buffer2) {
		ResumeThread(thread_handle);
		CloseHandle(thread_handle);

		return false;
	}

#ifdef _WIN64
	*(PDWORD)(instructions_and_info_buffer + 16) = context.Rip & 0xFFFFFFFF;
	*(PDWORD)(instructions_and_info_buffer + 24) = (context.Rip >> 32) & 0xFFFFFFFF;
	*(void**)(instructions_and_info_buffer + 32) = function;
	*(void**)(instructions_and_info_buffer + 42) = argument;
	*(void**)(instructions_and_info_buffer + 62) = (void*)((DWORD_PTR)instructions_and_info_buffer2 + 1);
#else
	*(PDWORD)(instructions_and_info_buffer + 11) = context.Eip;
	*(void**)(instructions_and_info_buffer + 17) = function;
	*(void**)(instructions_and_info_buffer + 22) = argument;
	*(void**)(instructions_and_info_buffer + 29) = (void*)((DWORD_PTR)instructions_and_info_buffer2 + 1);
	*(void**)(instructions_and_info_buffer + 36) = instructions_and_info_buffer2;
#endif

	WriteProcessMemory(process_handle, instructions_and_info_buffer2, instructions_and_info_buffer, sizeof(instructions_and_info_buffer), nullptr);

#ifdef _WIN64
	context.Rip = (DWORD64)instructions_and_info_buffer2 + 9;
#else
	context.Eip = (DWORD)instructions_and_info_buffer2 + 5;
#endif

	if (!SetThreadContext(thread_handle, &context)) {
		VirtualFreeEx(process_handle, instructions_and_info_buffer2, 0, MEM_RELEASE);
		ResumeThread(thread_handle);
		CloseHandle(thread_handle);

		return false;
	}

	ResumeThread(thread_handle);
	CloseHandle(thread_handle);

	bool returned = false;

	while (!returned)
		ReadProcessMemory(process_handle, instructions_and_info_buffer2, &returned, sizeof(bool), nullptr);

	ReadProcessMemory(process_handle, (void*)((DWORD_PTR)instructions_and_info_buffer2 + 1), ret, sizeof(DWORD_PTR), nullptr);

	VirtualFreeEx(process_handle, instructions_and_info_buffer2, 0, MEM_RELEASE);

	return true;
}

struct Data {
	LPVOID image_buffer;
	HMODULE (WINAPI *LoadLibraryA)(LPCSTR lpLibFileName);
	FARPROC (WINAPI *GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
#ifdef _WIN64
	BOOLEAN (__cdecl *RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif
};

BOOL __stdcall Shellcode(Data* data) {
	PIMAGE_DOS_HEADER image_dos_header = (PIMAGE_DOS_HEADER)data->image_buffer;
	PIMAGE_NT_HEADERS image_nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_dos_header + image_dos_header->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR image_import_descriptor = image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress ? (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) : nullptr;
	HMODULE library_handle;
	PIMAGE_THUNK_DATA image_thunk_data1, image_thunk_data2;
	FARPROC function;

	if (image_import_descriptor) {
		while (image_import_descriptor->Name) {
			library_handle = data->LoadLibraryA((LPCSTR)((DWORD_PTR)data->image_buffer + image_import_descriptor->Name));

			if (!library_handle)
				continue;

			image_thunk_data1 = (PIMAGE_THUNK_DATA)((DWORD_PTR)data->image_buffer + image_import_descriptor->OriginalFirstThunk);
			image_thunk_data2 = (PIMAGE_THUNK_DATA)((DWORD_PTR)data->image_buffer + image_import_descriptor->FirstThunk);

			while (image_thunk_data1->u1.AddressOfData) {
				if (IMAGE_SNAP_BY_ORDINAL(image_thunk_data1->u1.Ordinal))
					function = data->GetProcAddress(library_handle, MAKEINTRESOURCE(image_thunk_data1->u1.Ordinal));
				else
					function = data->GetProcAddress(library_handle, ((PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)data->image_buffer + image_thunk_data1->u1.AddressOfData))->Name);

				if (!function)
					continue;

				image_thunk_data2->u1.Function = (DWORD_PTR)function;

				++image_thunk_data1;
				++image_thunk_data2;
			}

			++image_import_descriptor;
		}
	}

	PIMAGE_DELAYLOAD_DESCRIPTOR image_delay_load_descriptor = image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress ? (PIMAGE_DELAYLOAD_DESCRIPTOR)((DWORD_PTR)data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress) : nullptr;

	if (image_delay_load_descriptor) {
		while (image_delay_load_descriptor->DllNameRVA) {
			library_handle = data->LoadLibraryA((LPCSTR)((DWORD_PTR)data->image_buffer + image_delay_load_descriptor->DllNameRVA));

			if (!library_handle)
				continue;

			image_thunk_data1 = (PIMAGE_THUNK_DATA)((DWORD_PTR)data->image_buffer + image_delay_load_descriptor->ImportNameTableRVA);
			image_thunk_data2 = (PIMAGE_THUNK_DATA)((DWORD_PTR)data->image_buffer + image_delay_load_descriptor->ImportAddressTableRVA);

			while (image_thunk_data1->u1.AddressOfData) {
				if (IMAGE_SNAP_BY_ORDINAL(image_thunk_data1->u1.Ordinal))
					function = data->GetProcAddress(library_handle, MAKEINTRESOURCE(image_thunk_data1->u1.Ordinal));
				else
					function = data->GetProcAddress(library_handle, ((PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)data->image_buffer + image_thunk_data1->u1.AddressOfData))->Name);

				if (!function)
					continue;

				image_thunk_data2->u1.Function = (DWORD_PTR)function;

				++image_thunk_data1;
				++image_thunk_data2;
			}

			++image_delay_load_descriptor;
		}
	}

	PIMAGE_BASE_RELOCATION image_base_relocation = image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress ? (PIMAGE_BASE_RELOCATION)((DWORD_PTR)data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) : nullptr;
	DWORD_PTR delta = (DWORD_PTR)data->image_buffer - image_nt_headers->OptionalHeader.ImageBase;

	if (image_base_relocation && delta) {
		int count;
		PWORD entries;
		DWORD offset;

		while (image_base_relocation->VirtualAddress) {
			count = (image_base_relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			entries = (PWORD)(image_base_relocation + 1);

			for (int i = 0; i < count; ++i) {
				offset = image_base_relocation->VirtualAddress + (entries[i] & 0xFFF);

				switch (entries[i] >> 12) {
#ifdef _WIN64
				case IMAGE_REL_BASED_DIR64:
#else
				case IMAGE_REL_BASED_HIGHLOW:
#endif
					*(PDWORD_PTR)((DWORD_PTR)data->image_buffer + offset) += delta;
					break;
				}
			}

			image_base_relocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)image_base_relocation + image_base_relocation->SizeOfBlock);
		}
	}

	PIMAGE_TLS_DIRECTORY image_tls_directory = image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress ? (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) : nullptr;

	if (image_tls_directory && image_tls_directory->AddressOfCallBacks) {
		PIMAGE_TLS_CALLBACK* image_tls_callbacks = (PIMAGE_TLS_CALLBACK*)image_tls_directory->AddressOfCallBacks;

		for (; *image_tls_callbacks; ++image_tls_callbacks)
			(*image_tls_callbacks)(data->image_buffer, DLL_PROCESS_ATTACH, nullptr);
	}

#ifdef _WIN64
	if (image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress)
		data->RtlAddFunctionTable((PRUNTIME_FUNCTION)((DWORD_PTR)data->image_buffer + image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress), image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION), (DWORD64)data->image_buffer);
#endif

	if (image_nt_headers->OptionalHeader.AddressOfEntryPoint)
		return ((BOOL (APIENTRY *)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved))((DWORD_PTR)data->image_buffer + image_nt_headers->OptionalHeader.AddressOfEntryPoint))((HMODULE)data->image_buffer, DLL_PROCESS_ATTACH, nullptr);

	return FALSE;
}

bool Inject(const char* process_name, const char* dll_path) {
	HANDLE file_handle = CreateFile(dll_path, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (file_handle == INVALID_HANDLE_VALUE)
		return false;

	DWORD file_size = GetFileSize(file_handle, nullptr);

	if (file_size == INVALID_FILE_SIZE) {
		CloseHandle(file_handle);

		return false;
	}

	LPVOID file_buffer = VirtualAlloc(nullptr, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!file_buffer) {
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

	if (!(image_nt_headers->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
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

	TOKEN_PRIVILEGES new_state;

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &new_state.Privileges[0].Luid)) {
		CloseHandle(token_handle);
		VirtualFree(file_buffer, 0, MEM_RELEASE);

		return false;
	}

	new_state.PrivilegeCount = 1;
	new_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token_handle, FALSE, &new_state, 0, nullptr, nullptr)) {
		CloseHandle(token_handle);
		VirtualFree(file_buffer, 0, MEM_RELEASE);

		return false;
	}

	CloseHandle(token_handle);

	int process_id = GetProcessID(process_name);

	if (process_id == -1) {
		VirtualFree(file_buffer, 0, MEM_RELEASE);

		return false;
	}

	HANDLE process_handle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, process_id);

	if (!process_handle) {
		VirtualFree(file_buffer, 0, MEM_RELEASE);

		return false;
	}

	LPVOID image_buffer = VirtualAllocEx(process_handle, nullptr, image_nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!image_buffer) {
		CloseHandle(process_handle);
		VirtualFree(file_buffer, 0, MEM_RELEASE);

		return false;
	}

	WriteProcessMemory(process_handle, image_buffer, file_buffer, image_nt_headers->OptionalHeader.SizeOfHeaders, nullptr);

	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(image_nt_headers);

	for (int i = 0; i < image_nt_headers->FileHeader.NumberOfSections; ++i) {
		if (!section_header[i].SizeOfRawData)
			continue;

		WriteProcessMemory(process_handle, (LPVOID)((DWORD_PTR)image_buffer + section_header[i].VirtualAddress), (LPCVOID)((DWORD_PTR)file_buffer + section_header[i].PointerToRawData), section_header[i].SizeOfRawData, nullptr);
	}

	Data data;
	data.image_buffer = image_buffer;
	data.LoadLibraryA = LoadLibraryA;
	data.GetProcAddress = GetProcAddress;
#ifdef _WIN64
	data.RtlAddFunctionTable = RtlAddFunctionTable;
#endif

	LPVOID data_buffer = VirtualAllocEx(process_handle, nullptr, sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!data_buffer) {
		VirtualFreeEx(process_handle, image_buffer, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		VirtualFree(file_buffer, 0, MEM_RELEASE);

		return false;
	}

	WriteProcessMemory(process_handle, data_buffer, &data, sizeof(data), nullptr);

	LPVOID shellcode_buffer = VirtualAllocEx(process_handle, nullptr, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!shellcode_buffer) {
		VirtualFreeEx(process_handle, data_buffer, 0, MEM_RELEASE);
		VirtualFreeEx(process_handle, image_buffer, 0, MEM_RELEASE);
		CloseHandle(process_handle);
		VirtualFree(file_buffer, 0, MEM_RELEASE);

		return false;
	}

	WriteProcessMemory(process_handle, shellcode_buffer, Shellcode, 2048, nullptr);

	BOOL ret = FALSE;

	if (!HijackThread(process_handle, shellcode_buffer, data_buffer, (PDWORD_PTR)&ret)) {
		HANDLE remote_thread_handle = CreateRemoteThread(process_handle, nullptr, 0, (LPTHREAD_START_ROUTINE)shellcode_buffer, data_buffer, 0, nullptr);

		if (!remote_thread_handle) {
			VirtualFreeEx(process_handle, shellcode_buffer, 0, MEM_RELEASE);
			VirtualFreeEx(process_handle, data_buffer, 0, MEM_RELEASE);
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
	VirtualFreeEx(process_handle, data_buffer, 0, MEM_RELEASE);

	if (!ret)
		VirtualFreeEx(process_handle, image_buffer, 0, MEM_RELEASE);
	else {
		auto WriteProcessMemory2 = [](HANDLE hProcess, LPVOID lpBaseAddress, SIZE_T nSize) -> BOOL {
			unsigned char* null_buffer = new unsigned char[nSize]();
			BOOL result = WriteProcessMemory(hProcess, lpBaseAddress, null_buffer, nSize, nullptr);
			delete[] null_buffer;

			return result;
		};

		WriteProcessMemory2(process_handle, image_buffer, image_nt_headers->OptionalHeader.SizeOfHeaders);

		for (int i = 0; i < image_nt_headers->FileHeader.NumberOfSections; ++i) {
			if (section_header[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
				if (!section_header[i].SizeOfRawData)
					continue;

				WriteProcessMemory2(process_handle, (LPVOID)((DWORD_PTR)image_buffer + section_header[i].VirtualAddress), section_header[i].SizeOfRawData);
			} else {
				auto get_protect = [&section_header, &i]() -> DWORD {
					if (section_header[i].Characteristics & IMAGE_SCN_MEM_READ)
						return (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READ : PAGE_READONLY;
					else if (section_header[i].Characteristics & IMAGE_SCN_MEM_WRITE)
						return (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

					return (section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE : PAGE_NOACCESS;
				};

				DWORD old_protect;
				VirtualProtectEx(process_handle, (LPVOID)((DWORD_PTR)image_buffer + section_header[i].VirtualAddress), section_header[i].Misc.VirtualSize, get_protect(), &old_protect);
			}
		}
	}

	CloseHandle(process_handle);
	VirtualFree(file_buffer, 0, MEM_RELEASE);

	return true;
}