/*
 *   Author           : 93aef0ce4dd141ece6f5
 *   Title            : crypt.c
 *   Description      : contains functions to apply
 *                      encrypting and PE modifications
 *
 * 
 *   Copyright (C) 2016  93aef0ce4dd141ece6f5
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <Windows.h>
#include <Winnt.h>

#include "Crypt.h"

UCHAR key[] = {0x0C, 0xA4, 0xF9, 0x16, 0xCA, 0x51};

UCHAR loader[] = {
                0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,     // lea  eax, .text address
                0x8D, 0x98, 0x00, 0x00, 0x00, 0x00,     // lea  ebx, [eax+SizeOfRawData]
                0x39, 0xD8,                             // cmp  eax, ebx
                0x74, 0x15,                             // je   (distance to loader)
                0x53,                                   // push ebx
                0x83, 0xFA, 0x06,                       // cmp  edx, size of key (6)
                0x7C, 0x02,                             // jl   xor instruction
                0x31, 0xD2,                             // xor  edx, edx
                0x8A, 0x9A, 0x00, 0x00, 0x00, 0x00,     // mov  bl, key array
                0x30, 0x18,                             // xor  BYTE [eax], bl
                0x5B,                                   // pop  ebx
                0x40,                                   // inc  eax
                0x42,                                   // inc  edx
                0xEB, 0xE7,                             // jmp  loop
                0x68, 0x00, 0x00, 0x00, 0x00,           // push OEP
                0xC3,                                   // ret
                0x0C, 0xA4, 0xF9, 0x16, 0xCA, 0x51      // key array
                };

PIMAGE_DOS_HEADER get_dos_header (PUCHAR file) {
    return (PIMAGE_DOS_HEADER)file;
}

PIMAGE_NT_HEADERS get_pe_header (PUCHAR file) {
    PIMAGE_DOS_HEADER pidh = get_dos_header (file);

    return (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
}

PIMAGE_FILE_HEADER get_file_header (PUCHAR file) {
    PIMAGE_NT_HEADERS pinh = get_pe_header (file);

    return (PIMAGE_FILE_HEADER)&pinh->FileHeader;
}

PIMAGE_OPTIONAL_HEADER get_optional_header (PUCHAR file) {
    PIMAGE_NT_HEADERS pinh = get_pe_header (file);

    return (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
}

PIMAGE_SECTION_HEADER get_first_section_header (PUCHAR file) {
    PIMAGE_NT_HEADERS pinh = get_pe_header (file);

    return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
}

PIMAGE_SECTION_HEADER get_last_section_header (PUCHAR file) {
    PIMAGE_FILE_HEADER pifh = get_file_header (file);
    PIMAGE_SECTION_HEADER pish = get_first_section_header (file);

    pish = (PIMAGE_SECTION_HEADER)((DWORD)pish + (pifh->NumberOfSections-1)
                                    * sizeof (IMAGE_SECTION_HEADER));

    return pish;
}

BOOL check_valid_file (PUCHAR file) {
    PIMAGE_DOS_HEADER pidh = get_dos_header (file);
    PIMAGE_NT_HEADERS pinh = get_pe_header (file);

    if (pidh->e_magic != IMAGE_DOS_SIGNATURE || 
        pinh->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    return TRUE;
}

static BOOL check_available_space (PIMAGE_SECTION_HEADER pish, SIZE_T num_sections) {
    // get first section offset
    DWORD first_section_offset = pish->PointerToRawData;

    // get last section
    DWORD empty_section_offset = (DWORD)pish + num_sections * sizeof (IMAGE_SECTION_HEADER);

    // check if space between first section and last section header has enough space
    // for a new section header
    if (first_section_offset - empty_section_offset < sizeof (IMAGE_SECTION_HEADER)) {
        return FALSE;
    }
    
    return TRUE;
}

static DWORD align (DWORD address, DWORD section_alignment) {
    return ((address + section_alignment - 1) / section_alignment) * section_alignment;
}

BOOL add_new_section (PUCHAR file, LPCSTR name, DWORD characteristics) {
    PIMAGE_FILE_HEADER pifh = get_file_header (file);
    PIMAGE_OPTIONAL_HEADER pioh = get_optional_header (file);
    PIMAGE_SECTION_HEADER pish = get_last_section_header (file);

    DWORD section_alignment = pioh->SectionAlignment;
    DWORD file_alignment = pioh->FileAlignment;

    DWORD section_size = sizeof (loader) + sizeof (DWORD);

    print_debug ("Checking space for new section");
    // check if there is space for a new section
    if (check_available_space (get_first_section_header (file), 
                                pifh->NumberOfSections) == FALSE) {
        return FALSE;
    }

    PIMAGE_SECTION_HEADER new_pish = (PIMAGE_SECTION_HEADER)((DWORD)pish + 
                                    sizeof (IMAGE_SECTION_HEADER));
    print_debug ("New section header \"%s\" at address 0x%08x", name, new_pish);

    print_debug ("Setting new section values");
    memcpy (new_pish->Name, name, MAX_SECTION_NAME);
    new_pish->VirtualAddress = align (pish->VirtualAddress + 
                                        pish->Misc.VirtualSize, 
                                        section_alignment);
    new_pish->Misc.VirtualSize = section_size;
    new_pish->SizeOfRawData = align (section_size, 
                                    file_alignment);
    new_pish->PointerToRawData = align (pish->PointerToRawData +
                                        pish->SizeOfRawData, 
                                        file_alignment);
    new_pish->PointerToRelocations = 0x00;
    new_pish->PointerToLinenumbers = 0x00;
    new_pish->NumberOfRelocations = 0x00;
    new_pish->NumberOfLinenumbers = 0x00;
    new_pish->Characteristics = characteristics;

    print_debug ("Updating headers");
    // update headers
    pifh->NumberOfSections++;
    pioh->SizeOfImage = align (pioh->SizeOfImage + section_size, 
                                section_alignment);
    pioh->SizeOfHeaders = align (pioh->SizeOfHeaders + 
                                sizeof (IMAGE_SECTION_HEADER), 
                                file_alignment);

    return TRUE;
}

static VOID int_to_array (PUCHAR array, DWORD integer, DWORD start) {
    array[start] = integer & 0xFF;
    array[start + 1] = (integer >> 8) & 0xFF;
    array[start + 2] = (integer >> 16) & 0xFF;
    array[start + 3] = (integer >> 24) & 0xFF;
}

VOID redirect_entry_point (PUCHAR file) {
    PIMAGE_OPTIONAL_HEADER pioh = get_optional_header (file);
    PIMAGE_SECTION_HEADER pish = get_first_section_header (file);
    pish->Characteristics |= IMAGE_SCN_MEM_WRITE;

    // save original entry point
    DWORD oep = pioh->AddressOfEntryPoint + pioh->ImageBase;

    // get size of .text
    DWORD size = pish->SizeOfRawData;

    // get address of .text section
    DWORD code_address = pish->VirtualAddress + pioh->ImageBase;

    pish = get_last_section_header (file);

    // adjust address of entry point to beginning of new section
    pioh->AddressOfEntryPoint = pish->VirtualAddress;

    // get address of key array
    DWORD key_address = pish->VirtualAddress + pioh->ImageBase + 
                        sizeof (loader) - sizeof (key);

    print_debug ("Writing loader");
    // write .text start address
    int_to_array (loader, code_address, 2);
    print_debug ("Code address @ 0x%08x", code_address);
    // write size of .text
    int_to_array (loader, size, 8);
    print_debug ("Size of \".text\" @ 0x%08x", size);
    // write key address
    int_to_array (loader, key_address, 26);
    print_debug ("Key address @ 0x%08x", key_address);
    // write jumper to oep
    int_to_array (loader, oep, 38);
    print_debug ("Original entry point @ 0x%08x", oep);
}

static VOID crypt_code (PUCHAR file, SIZE_T size) {
    PIMAGE_SECTION_HEADER pish = get_first_section_header (file);

    int i;
    for (i = 0; i < size; i++) {
        file[pish->PointerToRawData + i] ^= key[i % sizeof (key)];
    }
}

BOOL write_to_new_section (HANDLE hFile, PUCHAR file) {
    PIMAGE_SECTION_HEADER first_pish = get_first_section_header (file);
    // last section should be new section
    PIMAGE_SECTION_HEADER new_pish = get_last_section_header (file);

    DWORD new_file_size = new_pish->PointerToRawData + new_pish->SizeOfRawData;

    file = realloc (file, new_file_size);
    if (file == NULL) {
        return FALSE;
    }

    print_debug ("Writing to file offset: 0x%08x", new_pish->PointerToRawData);
    memset ((file + new_pish->PointerToRawData), 0, new_pish->SizeOfRawData);

    print_debug ("Obfuscating file: 0x%08x bytes", first_pish->SizeOfRawData);
    crypt_code (file, first_pish->SizeOfRawData);

    print_debug ("Injecting loader to: 0x%08x", file + new_pish->PointerToRawData);
    memcpy ((file + new_pish->PointerToRawData), loader, sizeof (loader));

    DWORD nWritten = 0;

    print_debug ("Writing to file");
    if (WriteFile (hFile, file, new_file_size, &nWritten, NULL) == FALSE) {
        return FALSE;
    }
    print_debug ("Wrote 0x%08x bytes", nWritten);

    return TRUE;
}