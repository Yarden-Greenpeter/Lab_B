
/*
1) check task 1a 1b 1c to make sure the functions read the file as needed
2) build a menu as specified in lab 1:(
3)implement part 2
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int littlEndian = 0;

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
    fprintf(stderr, "Please enter a new signature file name:");
    //wait for the user to input a signature file name and store it in the provided variable.
    fgets(fileName, 256, stdin);
    fileName[strcspn(fileName, "\n")] = 0;
}

// Function to read a virus from a file
virus* readVirus(FILE *file) {
    virus *v = malloc(sizeof(virus));
    fread(v, 1, 18, file);
    if(littlEndian) v->SigSize = ntohs(v->SigSize);
    v->sig = malloc(v->SigSize);
    fread(v->sig, 1, v->SigSize, file);
    return v;
}

//Function to determain if a file is little or big endian return 1 if so and 0 if not
int checkEndianness(FILE *file){
    char magic[4];  // Array of exactly 4 characters
    fread(magic, 1, 4, file);
    if (strcmp(magic, "VIRL") == 0) {
        littlEndian = 1;
        return 1;
    } else if (strcmp(magic, "VIRB") == 0) {
        littlEndian = 0;
        return 1;
    }
    return 0;
}

// Function to print a virus
void printVirus(virus *v,  FILE *stream) {
    printf(stream, "Virus name: %s\n", v->virusName);
    printf(stream, "Virus signature length: %u\n", v->SigSize);
    printf(stream, "Virus signature: ");
    for (int i = 0; i < v->SigSize; i++) {
        printf("%02X ", v->sig[i]);
    }
    printf("\n");
}

// Function to print the linked list
void list_print(link *virus_list, FILE *stream) {
    link *current = virus_list;
    while (current != NULL) {
        printVirus(current->vir, stream);
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
    //for each virus search for his signature in the file
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
    link *virus_list = NULL;

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
                //try to open the file
                FILE *file = fopen(sigFileName, "rb");
                if (!file) {
                    perror("Error opening file");
                    break;
                }
                //check for the four magic numbers at the beginning of the file
                if(!checkEndianness(file)){
                    //close file and break
                    perror("Error reading magic number\n");
                    fclose(file);
                    break;
                }
                //allocte the list with the viruses descriptions
                list_free(virus_list);
                virus_list = NULL;
                virus *v;
                while ((v = readVirus(file)) != NULL) {
                    virus_list = list_append(virus_list, v);
                }
                //close the file
                fclose(file);
                break;
            }
            case 2:
                list_print(virus_list, stdout);
                break;
            case 3: {
                if (strlen(sigFileName) == 0) {
                    printf("Please provide a suspected file name as a command-line argument.\n");
                    break;
                }
                
                FILE *file = fopen(sigFileName, "rb");
                int TenThousend = (10 << 10) - ((3*5)<<4); //we have to have some fun in this lab
                char buffer[TenThousend];
                unsigned int size = fread(buffer, 1, TenThousend, file);
                detect_virus(buffer, size, virus_list);
                fclose(file);
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
