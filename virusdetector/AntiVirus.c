#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// Structs:
typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char *sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

typedef void (*FunctionPtr)();

struct func_desc{
    char *name; 
    FunctionPtr function;
    } func_desc;

//Global Variables
int littlEndian = 0;
char sigFileName[256] = "signatures-L";
link *virus_list = NULL;

//Task functions and auxilury function:

//sets the variable sigFileName to the user input.
void SetSigFileName() {
    fprintf(stderr, "Please enter a new signature file name:");
    fgets(sigFileName, 256, stdin);
    sigFileName[strcspn(sigFileName, "\n")] = 0;
}

//reads through a file a single virus, constructs it and returns it.
//note: used 3 freads since trying with 2 lead to problems...
virus* readVirus(FILE *file) {
    char buffer[2];
    virus *v = malloc(sizeof(virus));
    if (v == NULL) {
        perror("Failed to allocate memory for virus");
        return NULL;
    }
    if (fread(buffer, 1, 2, file) != 2){ //could happen if the file is finished
        free(v);
        return NULL;
    }
    //set the size accourding to VIRL | VIRB.
    if(littlEndian){
        v->SigSize = (buffer[1] << 8) | buffer[0];
    }
    else{
        v->SigSize = (buffer[0] << 8) | buffer[1];
    }
    //set the name of the virus.
    if(fread(v->virusName, sizeof(char), 16, file) != 16){ //if the file is well parsed this if condition won't be met
        free(v);
        return NULL;
    }
    //set the size of the signature and set the signature to the virus.
    v->sig = malloc(v->SigSize);
    if (v->sig == NULL) {
        perror("Failed to allocate memory for virus signature");
        free(v);
        return NULL;
    }
    if(fread(v->sig, sizeof(unsigned char), v->SigSize, file) != v->SigSize){ //if the file is well parsed this if condition won't be met
        perror("Failed to read the virus signature");
        free(v->sig);
        free(v);
        return NULL;
    }
    return v;
}

//checks if the 4 first chars of the file are VIRL | VIRB and sets the global variable littlEndian accordingly.
//if the file pointer contained VIRL | VIRB at the first 4 chars returns 1 (true - operation succeded) else 0(false - operation aburted).
int checkEndianness(FILE *file){
    char magic[4];
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

//auxillary function to pring a virus struct, used to help printVirus and list_print.
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
    printf("\n");
}

//prints a virus v to the stderr
void printVirus(virus *v) {
    print_virus_to_stream(v, stderr);
}

// prints a list of viruses from the start to finish to a specified stream (different order then signatures-L..)
// doesn't alter the list given.
void list_print(link *virus_list, FILE *stream) {
    link *current = virus_list;
    while (current != NULL) {
        print_virus_to_stream(current->vir, stream);
        current = current->nextVirus;
    }
}

//add a virus to a list.
link* list_append(link *virus_list, virus *data) {
    link *newLink = malloc(sizeof(link));
    newLink->vir = data;
    newLink->nextVirus = virus_list;
    return newLink;
}

//frees a list memory alloctions and frees each item in the list.
void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link *next = virus_list->nextVirus;
        free(virus_list->vir->sig);
        free(virus_list->vir);
        free(virus_list);
        virus_list = next;
    }
}
//goes over a file and a list of viruses and searches for each virus (by signature) in the file
//if found prints to stderr a notice alert with some information
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

//returns a list off viruses signatures offsets in the file, this will help the program eliminate all the viruses in a corrupt file.
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

//recieve the place in the file where a virus was found and alters the char at the point with a RET commend (0xC3)
void neutralize_virus(char *fileName, int signatureOffset) {
    FILE *file = fopen(fileName, "rb+");
    fseek(file, signatureOffset, SEEK_SET);
    fwrite(&((unsigned char){0xC3}) ,sizeof(unsigned char) ,1 ,file);
    fclose(file);
}

//Menu functions:
void Set(){
    SetSigFileName();
}

void Load(){
    FILE *file = fopen(sigFileName, "rb");
    if (!file) {
        perror("Error opening file");
        return;
    }
    //check for the four magic numbers at the beginning of the file.
    if(!checkEndianness(file)){ //will enter if the file isn't well parsed.
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
//detect all viruses in sigFileName.
void Detect(){
    char buffer[10000] = {0};
    FILE *file = fopen(sigFileName, "rb");

    unsigned int size = fread(buffer, 1, 10000, file);
    fclose(file);
    detect_virus(buffer, size, virus_list);
}

//netrulize all viruses in sigFileName
void Netrulize(){
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

void print_menu(int size, struct func_desc menu[]){
    printf("\nSelect operation from the following menu by its number:\n");
    for(int i = 0 ; i < size ; i++)
        printf("(%d) %s\n", i, menu[i].name); 
}

int main(int argc, char *argv[]) {

    struct func_desc menu[] = {
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
