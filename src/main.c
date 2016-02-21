#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <Windows.h>
#include <Winnt.h>

#include "Crypt.h"

#define NAME 			".dtm"
#define CHARACTERISTICS IMAGE_SCN_MEM_EXECUTE | \
						IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE

static VOID die (LPCSTR s) {
	fprintf (stderr, "[!] %s error: %lu\n", s, GetLastError());
	ExitProcess (EXIT_FAILURE);
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

VOID print_usage (LPCSTR s) {
	fprintf(stderr, "Usage: %s [FILE TO BE CRYPTED] [OUTPUT FILE]\n", s);
	ExitProcess (EXIT_FAILURE);
}

int main (int argc, char *argv[]) {
	if (argc < 3) {
		print_usage (argv[0]);
	}

	// get file to be crypted
	PCHAR target_file = malloc (MAX_PATH);
	if (target_file == NULL) {
		die ("Malloc target file buffer");
	}

	GetCurrentDirectory (MAX_PATH, target_file);
	strncat (target_file, "\\", 2);
	strcat (target_file, argv[1]);

	// open to extract information
	print_debug ("Opening target file: %s", target_file);
	HANDLE hTargetFile = CreateFile (target_file, GENERIC_READ, 
									0, NULL, OPEN_EXISTING, 
									FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTargetFile == INVALID_HANDLE_VALUE) {
		free (target_file);
		die ("Create file");
	}

	// get crypted file path
	PCHAR crypted_file = malloc (MAX_PATH);
	if (crypted_file == NULL) {
		CloseHandle (hTargetFile);
		free (target_file);
		die ("Malloc crypted file buffer");
	}

	GetCurrentDirectory (MAX_PATH, crypted_file);
	strncat (crypted_file, "\\", 2);
	strcat (crypted_file, argv[2]);

	// open to extract information
	print_debug ("Creating crypted file: %s", crypted_file);
	HANDLE hCryptedFile = CreateFile (crypted_file, GENERIC_WRITE, 
									0, NULL, CREATE_ALWAYS, 
									FILE_ATTRIBUTE_NORMAL, NULL);
	if (hCryptedFile == INVALID_HANDLE_VALUE) {
		free (crypted_file);
		CloseHandle (hTargetFile);
		free (target_file);
		die ("Create file");
	}
	
	// get file size of file to be crypted + size of loader
	DWORD file_size = GetFileSize (hTargetFile, NULL);
	print_debug ("Target file size: 0x%08x", file_size);

	// make buffer to store target program
	PUCHAR file_buf = malloc (file_size);
	if (file_buf == NULL) {
		CloseHandle (hCryptedFile);
		free (crypted_file);
		CloseHandle (hTargetFile);
		free (target_file);
	}

	DWORD nRead = 0;

	// read target file into buffer
	print_debug ("Reading target file");
	// read file to be crypted into file buffer
	if (ReadFile (hTargetFile, file_buf, file_size, &nRead, NULL) == FALSE) {
		free (file_buf);
		CloseHandle (hCryptedFile);
		free (crypted_file);
		CloseHandle (hTargetFile);
		free (target_file);
		die ("Read target file");
	}
	print_debug ("Read 0x%08x bytes", nRead);

	// clean up unneeded variables
	CloseHandle (hTargetFile);
	free (target_file);

	if (add_new_section (file_buf, NAME, CHARACTERISTICS) == FALSE) {
		free (file_buf);
		CloseHandle (hCryptedFile);
		free (crypted_file);
		die ("Add new section");
	}

	print_debug ("Modifying entry point");
	redirect_entry_point (file_buf);

	print_debug ("Writing to new section");
	if (write_to_new_section (hCryptedFile, file_buf) == FALSE) {
		free (file_buf);
		CloseHandle (hCryptedFile);
		free (crypted_file);
		die ("Write to new section");
	}
	
	free (file_buf);
	CloseHandle (hCryptedFile);
	free (crypted_file);

	print_debug ("Finished");

	return EXIT_SUCCESS;
}