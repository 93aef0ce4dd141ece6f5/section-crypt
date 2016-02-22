/*
 *   Author           : 93aef0ce4dd141ece6f5
 *   Title            : Crypt.h
 *   Description      : function prototypes
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

#define MAX_SECTION_NAME 8

// main.c
// debug printer
VOID print_debug (LPCSTR, ...);

// crypt.c
BOOL check_valid_file (PUCHAR);
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