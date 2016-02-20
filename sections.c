#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <Windows.h>
#include <Winnt.h>

#include "Crypt.h"

#define KEY 0x0C

//UCHAR key[] = {0x0C, 0xA4, 0xF9, 0x16, 0xCA, 0x51};

UCHAR loader[] = {
				0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,		// lea	eax, [OEP]
				0x8D, 0x98, 0x00, 0x00, 0x00, 0x00,		// lea	ebx, [eax+SizeOfRawData]
				0x39, 0xD8, 							// cmp	eax, ebx
				0x74, 0x06,								// je 	(distance to loader)
				0x80, 0x30, 0x0C,						// xor	BYTE [eax], 0x7
				0x40,									// inc 	eax
				0xEB, 0xF6,								// jmp	loop
				0xB8, 0x00, 0x00, 0x00, 0x00, 			// mov 	eax, 0
				0xFF, 0xE0				   				// jmp 	eax
				};

// initialise new section header
PSECTION_HEADER new_section_header (VOID) {
	if (strlen (NAME) > MAX_SECTION_NAME) {
		return NULL;
	}

	PSECTION_HEADER my_pish = malloc (sizeof (*my_pish));
	if (my_pish == NULL) {
		return my_pish;
	}

	memset (my_pish->Name, 0, MAX_SECTION_NAME);
	memcpy (my_pish->Name, NAME, MAX_SECTION_NAME);
	my_pish->VirtualSize = 0x00;
	my_pish->VirtualAddress = 0x00;
	my_pish->SizeOfRawData = 0x00;
	my_pish->PointerToRawData = 0x00;
	my_pish->PointerToRelocations = 0x00;
	my_pish->PointerToLinenumbers = 0x00;
	my_pish->NumberOfRelocations = 0x00;
	my_pish->NumberOfLinenumbers = 0x00;
	my_pish->Characteristics = CHARACTERISTICS;

	return my_pish;
}

// free section header
VOID free_section_header (PSECTION_HEADER my_pish) {
	free (my_pish->Name);
	free (my_pish);
}

PIMAGE_DOS_HEADER get_dos_header (LPVOID hFile) {
	return (PIMAGE_DOS_HEADER)hFile;
}

PIMAGE_NT_HEADERS get_pe_header (LPVOID hFile) {
	PIMAGE_DOS_HEADER pidh = get_dos_header (hFile);

	return (PIMAGE_NT_HEADERS)((DWORD)pidh + pidh->e_lfanew);
}

PIMAGE_FILE_HEADER get_file_header (LPVOID hFile) {
	PIMAGE_NT_HEADERS pinh = get_pe_header (hFile);

	return (PIMAGE_FILE_HEADER)&pinh->FileHeader;
}

PIMAGE_OPTIONAL_HEADER get_optional_header (LPVOID hFile) {
	PIMAGE_NT_HEADERS pinh = get_pe_header (hFile);

	return (PIMAGE_OPTIONAL_HEADER)&pinh->OptionalHeader;
}

PIMAGE_SECTION_HEADER get_first_section_header (LPVOID hFile) {
	PIMAGE_NT_HEADERS pinh = get_pe_header (hFile);

	return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pinh);
}

VOID redirect_entry_point (LPVOID hFile, PSECTION_HEADER my_pish) {
	PIMAGE_OPTIONAL_HEADER pioh = get_optional_header (hFile);
	PIMAGE_SECTION_HEADER pish = get_first_section_header (hFile);
	// save original entry point
	DWORD oep = pioh->AddressOfEntryPoint + pioh->ImageBase;
	print_debug ("Original Virtual Entry Point Found: 0x%08x", oep);
	DWORD size = pish->SizeOfRawData;
	print_debug ("Size of \".text\" segment: 0x%08x", size);

	// adjust address of entry point to beginning of new section
	pioh->AddressOfEntryPoint = my_pish->VirtualAddress + pioh->ImageBase;

	print_debug ("Writing loader");
	// write oep
	loader[2] = oep & 0xFF;
	loader[3] = (oep >> 8) & 0xFF;
	loader[4] = (oep >> 16) & 0xFF;
	loader[5] = (oep >> 24) & 0xFF;

	// write size of .text
	loader[8] = size & 0xFF;
	loader[9] = (size >> 8) & 0xFF;
	loader[10] = (size >> 16) & 0xFF;
	loader[11] = (size >> 24) & 0xFF;

	// write oep into loader
	loader[23] = loader[2];
	loader[24] = loader[3];
	loader[25] = loader[4];
	loader[26] = loader[5];
}

static BOOL check_available_space (PIMAGE_SECTION_HEADER pish, SHORT num_sections) {
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

static DWORD boundary_alignment (DWORD address, DWORD section_alignment) {
	return ((address + section_alignment - 1) / section_alignment) * section_alignment;
}

static VOID set_new_pish (PIMAGE_SECTION_HEADER new_pish, PSECTION_HEADER my_pish) {
	// set values into new section header
	// copy name into new section header'my_pish name
	memcpy (new_pish->Name, my_pish->Name, MAX_SECTION_NAME);
	new_pish->VirtualAddress = my_pish->VirtualAddress;
	new_pish->Misc.VirtualSize = my_pish->VirtualSize;
	new_pish->SizeOfRawData = my_pish->SizeOfRawData;
	new_pish->PointerToRawData = my_pish->PointerToRawData;
	new_pish->PointerToRelocations = my_pish->PointerToRelocations;
	new_pish->PointerToLinenumbers = my_pish->PointerToLinenumbers;
	new_pish->NumberOfRelocations = my_pish->NumberOfRelocations;
	new_pish->NumberOfLinenumbers = my_pish->NumberOfLinenumbers;
	new_pish->Characteristics = my_pish->Characteristics;
}

BOOL add_new_section (HANDLE hFile, PSECTION_HEADER my_pish) {
	PIMAGE_FILE_HEADER pifh = get_file_header (hFile);
	PIMAGE_OPTIONAL_HEADER pioh = get_optional_header (hFile);
	PIMAGE_SECTION_HEADER pish = get_first_section_header (hFile);

	DWORD section_alignment = pioh->SectionAlignment;
	DWORD file_alignment = pioh->FileAlignment;

	DWORD section_size = sizeof (loader) + sizeof (DWORD);

	print_debug ("Checking space for new section");
	// check if there is space for a new section
	if (check_available_space (pish, pifh->NumberOfSections) == FALSE) {
		return FALSE;
	}

	// set .text to be writable
	pish->Characteristics |= IMAGE_SCN_MEM_WRITE;

	// point new_pish to start of new section address

	PIMAGE_SECTION_HEADER new_pish = (PIMAGE_SECTION_HEADER)((DWORD)
									pish + pifh->NumberOfSections * 
									sizeof (IMAGE_SECTION_HEADER));

	// get last section header
	pish = (PIMAGE_SECTION_HEADER)((DWORD)pish + (pifh->NumberOfSections-1)
								* sizeof (IMAGE_SECTION_HEADER));

	printf ("[*] Last section at address 0x%08x\n", pish);

	printf ("[*] New section header \"%s\" at address 0x%08x\n", my_pish->Name, new_pish);

	print_debug ("Setting new section values");
	//new_pish->Name = my_pish->Name;

	my_pish->VirtualAddress = boundary_alignment (pish->VirtualAddress + 
												pish->Misc.VirtualSize, 
												section_alignment);
	my_pish->VirtualSize = section_size;
	my_pish->SizeOfRawData = boundary_alignment (section_size, 
												file_alignment);
	my_pish->PointerToRawData = boundary_alignment (pish->PointerToRawData +
													pish->SizeOfRawData, 
													file_alignment);
	set_new_pish (new_pish, my_pish);

	print_debug ("Updating headers");
	// update headers
	pifh->NumberOfSections++;
	//pioh->SizeOfCode += new_pish->SizeOfRawData;
	//pioh->CheckSum = 0xB860;
	//pioh->SizeOfUninitializedData = 0;
	pioh->SizeOfImage = boundary_alignment (pioh->SizeOfImage + section_size, 
											section_alignment);
	pioh->SizeOfHeaders = boundary_alignment (pioh->SizeOfHeaders + 
											sizeof (IMAGE_SECTION_HEADER), 
											file_alignment);

	return TRUE;
}

static VOID crypt_code (PUCHAR file, SIZE_T size) {
	PIMAGE_SECTION_HEADER pish = get_first_section_header ((HANDLE)file);

	int i;
	for (i = 0; i < size; i++) {
		file[pish->PointerToRawData + i] ^= KEY; //key[i % sizeof (key)];
	}
}

BOOL write_to_section (HANDLE hFile, HANDLE hNewFile, PSECTION_HEADER my_pish) {
	DWORD nRead = 0, nWritten = 0;
	DWORD file_size = my_pish->PointerToRawData + my_pish->SizeOfRawData;
	// lsat section file offset + its size = file size
	PUCHAR file = malloc (file_size);
	if (file == NULL) {
		return FALSE;
	}
	print_debug ("New section header at file offset: 0x%08x", my_pish);

	print_debug ("Reading from file");
	if (ReadFile (hFile, file, file_size, &nRead, NULL) == FALSE) {
		return FALSE;
	}
	print_debug ("Read %lu bytes", nRead);

	print_debug ("Writing to file offset: 0x%08x", my_pish->PointerToRawData);
	memset ((file + my_pish->PointerToRawData), 0, my_pish->SizeOfRawData);

	PIMAGE_SECTION_HEADER pish = get_first_section_header ((HANDLE)file);

	print_debug ("Obfuscating file: %lu bytes", pish->SizeOfRawData);
	crypt_code (file, pish->SizeOfRawData);

	print_debug ("Injecting loader");
	memcpy ((file + my_pish->PointerToRawData), loader, sizeof (loader));

	if (SetFilePointer (hFile, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		return FALSE;
	}

	print_debug ("Writing to file");
	if (WriteFile (hNewFile, file, file_size, &nWritten, NULL) == FALSE) {
		return FALSE;
	}
	print_debug ("Wrote %lu bytes", nWritten);

	return TRUE;
}