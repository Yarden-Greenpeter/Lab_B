/*
In this lab you will be writing a virusDetector program,
to detect computer viruses in a given suspected file.
NAME
   virusDetector - detects a virus in a file from a given set of viruses
SYNOPSIS
   virusDetector FILE
DESCRIPTION
   virusDetector compares the content of the given FILE byte-by-byte with a pre- 
   defined set of viruses described in the file. The comparison is done according
   to a naive   algorithm described in task 2.
   FILE - the suspected file

Part 1: Virus detector using Linked Lists
In the current part you are required to read the signatures of the viruses from 
the signatures file and to store these signatures in a dedicated linked list 
data structure. Note, that the command-line argument FILE is not used in subparts 1a 
and 1b below. At a later stage (part 1c) you will compare the virus signatures from 
the list to byte sequences from a suspected file, named in the command-line argument.

Part 1a - Reading a binary file into memory buffers
The signatures file begins with a magic number of 4 bytes, 
that is used to quickly check that this is the right type of file, 
followed immediately by the details of different viruses in a specific format. 
The magic number of the signature file is the character sequence "VIRL" for little-endian 
encoding, and "VIRB" for big-endian encoding. The rest of the file (after the magic number) 
consists of blocks (< N,name,signature>) where each block represents 
a single virus description.

Notice the format is little endian - the numbers (i.e., the length of the virus) 
are represented in little endian order.

The name of the virus is a null terminated string that is stored in 16 bytes. 
If the length of the actual name is less than 16, 
then the rest of the bytes are padded with null characters.

The layout of each block is as follows:

offset	size (in bytes)	description
0	2	The virus's signature length N, up to 2^16 little endian or 
        big endian depending on magic number
2	16	The virus name represented as a null terminated string
18	N	The virus signature
For example, the following hexadecimal signature (little endian version):
05 00 56 49 52 55 53 00 00 00 00 00 00 00 00 00 00 00 31 32 33 34 35
represents a 5-byte length virus, whose signature (viewed as hexadecimal) is:

31 32 33 34 35
and its name is VIRUS


You are given the following struct that represents a virus description. 
You are required to use it in your implementation of all the tasks.

typedef struct virus {
unsigned short SigSize;
char virusName[16];
unsigned char* sig;
} virus;


First, you are required to implement the following two auxiliary functions and use them for 
implementing the main parts:

void SetSigFileName( ): This function queries the user for a new signature file name, 
and sets the signature file name accordingly. The default file name 
(before this function is called) should be "signatures-L" (without the quotes).
virus* readVirus(FILE*): this function receives a file pointer and returns a virus* 
that represents the next virus in the file. To read from a file, use fread(). 
See man fread(3) for assistance.
void printVirus(virus* virus): this function receives a pointer to a virus structure. 
The function prints the virus data to stdout. It prints the virus name (in ASCII), 
the virus signature length (in decimal), and the virus signature (in hexadecimal representation).
After you implemented the auxiliary functions, implement the following two steps:

Open the current signatures file, check the magic number, and print an error message and 
exit if the magic number is incorrect (i.e. different from "VIRL"or "VIRB") 
Then if magic number is OK, use readVirus in order to read the viruses one-by-one, 
and use printVirus in order to print the virus to the standard output.
Test your implementation by comparing your output with the file. Tip for Linux: use diff to
compare files line by line. (type man diff for more info)
Reading into structs
The structure of the virus description on file allows reading an entire description into 
a virus struct in 2 fread calls. You should read the first 18 bytes directly into the virus 
struct. You may need to manipulate the size field. Then, according to the size, 
allocate memory for sig and read the signature directly into it.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define the virus struct
typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char *sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

// Function to set the signature file name
void SetSigFileName(char *fileName) {
    printf("Enter signature file name: ");
    fgets(fileName, 256, stdin);
    fileName[strcspn(fileName, "\n")] = 0;  // Remove the newline character
}

// Function to read a virus from a file
virus* readVirus(FILE *file) {
    virus *v = malloc(sizeof(virus));
    if (fread(v, 1, 18, file) != 18) {  // Read the first 18 bytes
        free(v);
        return NULL;
    }

    // Adjust the signature length if needed
    if (v->SigSize > 0) {
        v->sig = malloc(v->SigSize);
        if (fread(v->sig, 1, v->SigSize, file) != v->SigSize) {
            free(v->sig);
            free(v);
            return NULL;
        }
    } else {
        v->sig = NULL;
    }
    return v;
}

// Function to print a virus
void printVirus(virus *v) {
    printf("Virus name: %s\n", v->virusName);
    printf("Virus signature length: %u\n", v->SigSize);
    printf("Virus signature: ");
    for (int i = 0; i < v->SigSize; i++) {
        printf("%02X ", v->sig[i]);
    }
    printf("\n");
}

// Function to print the linked list
void list_print(link *virus_list, FILE *stream) {
    link *current = virus_list;
    while (current != NULL) {
        printVirus(current->vir);
        current = current->nextVirus;
    }
}

// Function to append a new virus to the list
link* list_append(link *virus_list, virus *data) {
    link *newLink = malloc(sizeof(link));
    newLink->vir = data;
    newLink->nextVirus = virus_list;
    return newLink;
}

// Function to free the linked list
void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link *next = virus_list->nextVirus;
        free(virus_list->vir->sig);
        free(virus_list->vir);
        free(virus_list);
        virus_list = next;
    }
}

// Function to detect viruses in a buffer
void detect_virus(char *buffer, unsigned int size, link *virus_list) {
    link *current = virus_list;
    while (current != NULL) {
        virus *v = current->vir;
        for (unsigned int i = 0; i <= size - v->SigSize; i++) {
            if (memcmp(buffer + i, v->sig, v->SigSize) == 0) {
                printf("Virus detected!\n");
                printf("Starting byte: %u\n", i);
                printf("Virus name: %s\n", v->virusName);
                printf("Virus signature size: %u\n", v->SigSize);
            }
        }
        current = current->nextVirus;
    }
}

int main(int argc, char *argv[]) {
    char sigFileName[256] = "signatures-L";
    char suspectedFileName[256] = "";
    link *virus_list = NULL;

    if (argc > 1) {
        strncpy(suspectedFileName, argv[1], 255);
    }

    while (1) {
        printf("0) Set signatures file name\n");
        printf("1) Load signatures\n");
        printf("2) Print signatures\n");
        printf("3) Detect viruses\n");
        printf("4) Fix file\n");
        printf("5) Quit\n");

        int option;
        char input[256];
        fgets(input, sizeof(input), stdin);
        sscanf(input, "%d", &option);

        switch (option) {
            case 0:
                SetSigFileName(sigFileName);
                break;
            case 1: {
                FILE *file = fopen(sigFileName, "rb");
                if (!file) {
                    perror("Error opening file");
                    break;
                }

                // Read and check the magic number
                char magic[5] = {0};
                if (fread(magic, 1, 4, file) != 4) {
                    fprintf(stderr, "Error reading magic number\n");
                    fclose(file);
                    break;
                }
                if (strcmp(magic, "VIRL") != 0 && strcmp(magic, "VIRB") != 0) {
                    fprintf(stderr, "Invalid magic number\n");
                    fclose(file);
                    break;
                }

                // Free the existing list if any
                list_free(virus_list);
                virus_list = NULL;

                // Create and populate the linked list
                virus *v;
                while ((v = readVirus(file)) != NULL) {
                    virus_list = list_append(virus_list, v);
                }

                fclose(file);
                break;
            }
            case 2:
                list_print(virus_list, stdout);
                break;
            case 3: {
                if (strlen(suspectedFileName) == 0) {
                    printf("Please provide a suspected file name as a command-line argument.\n");
                    break;
                }
                
                FILE *suspectedFile = fopen(suspectedFileName, "rb");
                if (!suspectedFile) {
                    perror("Error opening suspected file");
                    break;
                }

                char buffer[10000];
                unsigned int size = fread(buffer, 1, sizeof(buffer), suspectedFile);
                detect_virus(buffer, size, virus_list);
                fclose(suspectedFile);
                break;
            }
            case 4:
                printf("Not implemented\n");
                break;
            case 5:
                list_free(virus_list);
                return 0;
            default:
                printf("Invalid option\n");
                break;
        }
    }
}
