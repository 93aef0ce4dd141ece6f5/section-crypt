/*
 *   Author           : 93aef0ce4dd141ece6f5
 *   Title            : main.c
 *   Description      : main function
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
#include <stdarg.h>
#include <Windows.h>
#include <Winnt.h>

#include "Crypt.h"

#define DEBUG

#define NAME            ".dtm\0\0\0"
#define CHARACTERISTICS IMAGE_SCN_MEM_EXECUTE | \
                        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE

/*
 * function to process any errors
 * which occur, then exits the program
 */
static VOID die (LPCSTR s) {
    fprintf (stderr, "[!] %s error: %lu\n", s, GetLastError());
    ExitProcess (EXIT_FAILURE);
}

/*
 * prints any debugging statements
 * undefine DEBUG to disable this
 */
VOID print_debug (LPCSTR fmt, ...) {
#ifdef DEBUG
    CHAR buf[BUFSIZ];

    strcpy (buf, "[*] ");

    va_list args;
    va_start (args, fmt);

    vsnprintf (buf + strlen (buf), sizeof (buf) - strlen (buf), fmt, args);

    fprintf (stdout, "%s\n", buf);

    va_end (args);
#endif
}

/*
 * simply prints the usage of
 * the program if the user fails
 * to provide correct command arguments
 */
VOID print_usage (LPCSTR s) {
    fprintf(stderr, "Usage: %s [FILE TO BE CRYPTED] [OUTPUT FILE]\n", s);
    ExitProcess (EXIT_FAILURE);
}

/*
 * main function of course
 */
int main (int argc, char *argv[]) {
    /*
     * check for correct number of
     * command arguments
     */
    if (argc < 3) {
        print_usage (argv[0]);
    }

    /*
     * this is a buffer for the path
     * to the exectuable which is to
     * be crypted
     * must be in the same directory
     */
    PCHAR target_file = malloc (MAX_PATH);
    if (target_file == NULL) {
        die ("Malloc target file buffer");
    }

    GetCurrentDirectory (MAX_PATH, target_file);
    strncat (target_file, "\\", 2);
    strcat (target_file, argv[1]);

    /*
     * open the program to be crpyted so
     * that we can read its binary contents
     * and extract its information like its
     * headers and section data
     */
    print_debug ("Opening target file: %s", target_file);
    HANDLE hTargetFile = CreateFile (target_file, GENERIC_READ, 
                                    0, NULL, OPEN_EXISTING, 
                                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTargetFile == INVALID_HANDLE_VALUE) {
        free (target_file);
        die ("Create file");
    }

    /*
     * another buffer to hold the path
     * to the output crypted file
     * outputs to the same directory
     */
    PCHAR crypted_file = malloc (MAX_PATH);
    if (crypted_file == NULL) {
        CloseHandle (hTargetFile);
        free (target_file);
        die ("Malloc crypted file buffer");
    }

    GetCurrentDirectory (MAX_PATH, crypted_file);
    strncat (crypted_file, "\\", 2);
    strcat (crypted_file, argv[2]);

    /*
     * open a file to be created
     * so we can output the crypted
     * file
     */
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
    
    /*
     * we need the file size of the 
     * file to be crypted so that we
     * know how much space our file
     * buffer needs
     */
    DWORD file_size = GetFileSize (hTargetFile, NULL);
    print_debug ("Target file size: 0x%08x", file_size);

    /*
     * make a dynamic buffer to store
     * the contents of the to-be-crypted
     * file
     * we'll need to modify this size later
     * to be able to store our new section
     */
    PUCHAR file_buf = malloc (file_size);
    if (file_buf == NULL) {
        CloseHandle (hCryptedFile);
        free (crypted_file);
        CloseHandle (hTargetFile);
        free (target_file);
    }

    DWORD nRead = 0;

    /* 
     * reading the binary of the target
     * file into the buffer we just made
     * up to the size of the file
     */
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

    /*
     * we can now close our target
     * file because we no longer 
     * need it
     * don't forget to free the 
     * path buffer too!
     */
    CloseHandle (hTargetFile);
    free (target_file);

    /*
     * we need to check if the file
     * is appropriate or not
     */
    if (check_valid_file (file_buf) == FALSE) {
        free (file_buf);
        CloseHandle (hCryptedFile);
        free (crypted_file);
        die ("Invalid input file");
    }

    /*
     * add a new section header
     * and initialise values and
     * update headers
     */
    if (add_new_section (file_buf, NAME, CHARACTERISTICS) == FALSE) {
        free (file_buf);
        CloseHandle (hCryptedFile);
        free (crypted_file);
        die ("Add new section");
    }

    /* 
     * modify the original entry
     * point to our new section's
     * and also modify the loader
     * routine's values
     */
    print_debug ("Modifying entry point");
    redirect_entry_point (file_buf);

    /*
     * now we need to actually
     * write into our new section
     * including the loader routine
     */
    print_debug ("Writing to new section");
    if (write_to_new_section (hCryptedFile, file_buf) == FALSE) {
        free (file_buf);
        CloseHandle (hCryptedFile);
        free (crypted_file);
        die ("Write to new section");
    }
    
    /*
     * clean up some of our
     * handles and buffers
     */
    free (file_buf);
    CloseHandle (hCryptedFile);
    free (crypted_file);

    print_debug ("Finished");

    return EXIT_SUCCESS;
}