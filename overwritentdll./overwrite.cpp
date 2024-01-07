#include <iostream>
#include <windows.h>
#include <Psapi.h>

#pragma warning(disable : 6387)

int main()
{
    HANDLE current = GetCurrentProcess();

    MODULEINFO mi = { 0 };
    STARTUPINFO si = { sizeof si };
    PROCESS_INFORMATION pi;

    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(L"ntdll.dll"), &mi, sizeof(MODULEINFO));

    PIMAGE_DOS_HEADER hooked_dos = (PIMAGE_DOS_HEADER)mi.lpBaseOfDll;
    PIMAGE_NT_HEADERS hooked_nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)mi.lpBaseOfDll + hooked_dos->e_lfanew);

    if (CreateProcessW(L"c:\\\\windows\\system32\\calc.exe", nullptr, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    {
        LPVOID pNtDll = HeapAlloc(GetProcessHeap(), 0, mi.SizeOfImage);

        ZeroMemory(pNtDll, 0);

        SIZE_T read;

        if (ReadProcessMemory(pi.hProcess, (LPCVOID)mi.lpBaseOfDll, pNtDll, mi.SizeOfImage, &read))
        {
            std::cout << "success reading process memory" << std::endl;

            PIMAGE_DOS_HEADER fresh_dos = (PIMAGE_DOS_HEADER)pNtDll;
            PIMAGE_NT_HEADERS fresh_nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)pNtDll + fresh_dos->e_lfanew);

            for (WORD i = 0; i < hooked_nt->FileHeader.NumberOfSections; i++)
            {
                PIMAGE_SECTION_HEADER hooked_section = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(hooked_nt) + ((ULONG_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

                if (strcmp((PCHAR)hooked_section->Name, ".text") == 0)
                {
                    DWORD oldProtect = 0;
                    LPVOID hooked_text_section = (LPVOID)((ULONG_PTR)mi.lpBaseOfDll + (DWORD_PTR)hooked_section->VirtualAddress);

                    LPVOID fresh_text_section = (LPVOID)((ULONG_PTR)pNtDll + (DWORD_PTR)hooked_section->VirtualAddress);

                    VirtualProtect(hooked_text_section, hooked_section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

                    RtlCopyMemory(hooked_text_section, fresh_text_section, hooked_section->Misc.VirtualSize);

                    VirtualProtect(hooked_text_section, hooked_section->Misc.VirtualSize, oldProtect, &oldProtect);

                    break;
                }
            }

            CloseHandle(pi.hThread);
            TerminateProcess(pi.hProcess, 0);
        }
        else
        {
            std::cout << "error reading process memory " << GetLastError() << std::endl;
        }
    }

    return 0;
}

