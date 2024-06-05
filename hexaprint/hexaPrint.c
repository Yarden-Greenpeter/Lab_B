/*
write a program that receives the name of a binary file as a command-line argument,
and prints the hexadecimal value of each byte in the file in sequence
to the standard output (using printf). Consult the printf(3) man page for 
hexadecimal format printing.

NAME
    hexaPrint - prints the hexdecimal value of the input bytes from a given file
SYNOPSIS
    hexaPrint FILE
DESCRIPTION
    hexaPrint receives, as a command-line argument, the name of a "binary" file, and prints the hexadecimal value of each byte to the standard output, separated by spaces.
For example, your program will print the following output for this exampleFile (download using right click, save as):

#>hexaPrint exampleFile
63 68 65 63 6B AA DD 4D 79 0C 48 65 78

You should implement this program using:
fread(3) to read data from the file into memory.
A helper function, PrintHex(buffer, length), that prints length bytes from memory location buffer, in hexadecimal format.
You will need the helper function during the rest of the assignment, so make sure it is well written and debugged.
Additionally,*/



#include <stdio.h>
#include <stdlib.h>

void PrintHex(const unsigned char *buffer, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

int FileSize (FILE *file){
    fseek(file, 0, SEEK_END); 
    long file_size = ftell(file);
    rewind(file);
    return file_size;
}

int main(int argc, char *argv[]) {
    FILE *file = fopen(argv[1], "rb"); // Open in binary mode
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    int size = FileSize(file);
    unsigned char *buffer = malloc(size);
    fread(buffer, 1, size, file); // Read the file into the buffer
    PrintHex(buffer, size);
    free(buffer);
    fclose(file);
    return 1;
}