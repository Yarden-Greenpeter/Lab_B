
/*
1) build a menu as specified in lab 1:(
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char *sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

int littlEndian = 0;
char sigFileName[256] = "signatures-L";
link *virus_list = NULL;

void SetSigFileName() {
    fprintf(stderr, "Please enter a new signature file name:");
    fgets(sigFileName, 256, stdin);
    sigFileName[strcspn(sigFileName, "\n")] = 0;
}

virus* readVirus(FILE *file) {
    char buffer[2];
    virus *v = malloc(sizeof(virus));
    if (v == NULL) {
        perror("Failed to allocate memory for virus");
        return NULL;
    }
    if (fread(buffer, 1, 2, file) != 2){
        free(v);
        return NULL;
    }
    if(littlEndian){
        v->SigSize = (buffer[1] << 8) | buffer[0];
    }
    else{
        v->SigSize = (buffer[0] << 8) | buffer[1];
    }
    if(fread(v->virusName, sizeof(char), 16, file) != 16){
        free(v);
        return NULL; // Read error
    }
    
    v->sig = malloc(v->SigSize);
    if (v->sig == NULL) {
        perror("Failed to allocate memory for virus signature");
        free(v);
        return NULL;
    }
    if(fread(v->sig, sizeof(unsigned char), v->SigSize, file) != v->SigSize){
        perror("Failed to read the virus signature");
        free(v->sig);
        free(v);
        return NULL; // Read error
    }
    return v;
}

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

void print_virus_to_stream(virus *v,  FILE *stream) {
    fprintf(stream, "Virus name: %s\n", v->virusName);
    fprintf(stream, "Virus size: %d\n", v->SigSize);
    fprintf(stream, "signature: ");
    for (int i = 0; i < v->SigSize; i++) {
        fprintf(stream, "%02X", v->sig[i]);
        if(i < v->SigSize-1){
            fprintf(stream, " ");
        }
    }
    printf("\n\n");
}

void printVirus(virus *v) {
    print_virus_to_stream(v, stderr);
}

void list_print(link *virus_list, FILE *stream) {
    link *current = virus_list;
    while (current != NULL) {
        print_virus_to_stream(current->vir, stream);
        current = current->nextVirus;
    }
}

link* list_append(link *virus_list, virus *data) {
    link *newLink = malloc(sizeof(link));
    newLink->vir = data;
    newLink->nextVirus = virus_list;
    return newLink;
}

void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link *next = virus_list->nextVirus;
        free(virus_list->vir->sig);
        free(virus_list->vir);
        free(virus_list);
        virus_list = next;
    }
}

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

int* detect_virus_offsets(char *buffer, unsigned int size, link *virus_list){
    link* current = virus_list;
    int numViruses = 0;
    int* offsets = malloc((size/16) * sizeof(int)); // size of buffer divided by virus_name_size to get the max num of possible viruses
    if (offsets == NULL) {
        perror("Error allocating memory for offsets");
        exit(EXIT_FAILURE);
    }
    while(current != NULL){
        virus* virus = current->vir;
        for (unsigned int i = 0; i <= size - virus->SigSize; i++) {
            if (memcmp(buffer + i, virus->sig, virus->SigSize) == 0) {
                offsets[numViruses] = i;
                numViruses++;
            }
        }
        current = current->nextVirus;
    }
    // Resize the array to fit the actual number of viruses detected
    offsets = realloc(offsets, numViruses * sizeof(int));
    return offsets;
}
//Task 2

void neutralize_virus(char *fileName, int signatureOffset) {
    FILE *file = fopen(fileName, "rb+");
    fseek(file, signatureOffset, SEEK_SET);
    fwrite(&((unsigned char){0xC3}) ,sizeof(unsigned char) ,1 ,file);
    fclose(file);
}

//extra auxilary functions
void Set(){
    SetSigFileName();
}

void Load(){
    FILE *file = fopen(sigFileName, "rb");
    if (!file) {
        perror("Error opening file");
        return;
    }
    //check for the four magic numbers at the beginning of the file
    if(!checkEndianness(file)){
    //close file and break
    perror("Error reading magic number\n");
    fclose(file);
    return;
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
}

void Print(){
    list_print(virus_list, stderr);
}

void Detect(){
    if (strlen(sigFileName) == 0) {
        printf("Please provide a suspected file name as a command-line argument.\n");
        return;
    }

    char buffer[10000] = {0};
    FILE *file = fopen(sigFileName, "rb");
    unsigned int size = fread(buffer, 1, 10000, file);
    fclose(file);
    detect_virus(buffer, size, virus_list);
}
//netrulize all viruses
void Netrulize(){
    if (strlen(sigFileName) == 0) {
        printf("Please provide a suspected file name as a command-line argument.\n");
        return;
    }
    //
    char buffer[10000] = {0};
    FILE *file = fopen(sigFileName, "rb");
    unsigned int size = fread(buffer, 1, 10000, file);
    fclose(file);
    int* offsets = detect_virus_offsets(buffer, (unsigned int)size, virus_list);
    for(int i = 0 ; i < sizeof(offsets) ; i++){
        neutralize_virus(sigFileName, offsets[i]);
    }
    free(offsets);
}

void Quit(){
    printf("Exiting program...\n");
    list_free(virus_list);
    exit(EXIT_SUCCESS);
}

typedef void (*FunctionPtr)();

struct fun_desc{char *name; FunctionPtr function;};

void print_menu(int size, struct fun_desc menu[]){
    printf("\nSelect operation from the following menu by its number:\n");
    for(int i = 0 ; i < size ; i++)
        printf("(%d) %s\n", i, menu[i].name); 
}

int main(int argc, char *argv[]) {

    struct fun_desc menu[] = {
        {"Set signatures file name", Set}, // Set signatures file name, calls SetSigFileName(). 
        {"Load signatures", Load}, // Load signatures, uses the current signatures file name.
        {"Print signatures", Print}, // Print the loaded signatures to the screen. If no file is loaded, nothing is printed.
        {"Detect viruses", Detect}, // Scan the buffer and print virus details if detected
        {"Fix file", Netrulize}, // Fix the virus
        {"Quit", Quit}, // Exit the program
        {NULL, NULL}
    };
    int menu_size = (sizeof(menu) / sizeof(menu[0])) - 1;
    char input[256];

    while(1){
        print_menu(menu_size, menu);
        fgets(input, sizeof(input), stdin);
        int option = atoi(input);
        if((option < 0) || (option >= menu_size)){
            printf("Invalid input, try again...\n");
            break;
        }
        else
            ((void (*)())menu[option].function)();
    }

    return 0;


}
