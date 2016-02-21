#define MAX_SECTION_NAME 8

// main.c
// debug printer
VOID print_debug (LPCSTR, ...);

// crypt.c
// extract headers from target file
PIMAGE_DOS_HEADER get_dos_header (PUCHAR);
PIMAGE_NT_HEADERS get_pe_header (PUCHAR);
PIMAGE_FILE_HEADER get_file_header (PUCHAR);
PIMAGE_OPTIONAL_HEADER get_optional_header (PUCHAR);
PIMAGE_SECTION_HEADER get_first_section_header (PUCHAR);
PIMAGE_SECTION_HEADER get_last_section_header (PUCHAR);

BOOL add_new_section (PUCHAR, LPCSTR, DWORD);
BOOL write_to_new_section (HANDLE, PUCHAR);
VOID redirect_entry_point (PUCHAR);