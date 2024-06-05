# Compiler
CC = gcc
CFLAGS = -Wall -Wextra -std=c11

# Executables
BUBBLESORT_TARGET = bubblesort
HEXAPRINT_TARGET = hexaPrint

# Source files
BUBBLESORT_SRC = bubblesort.c
HEXAPRINT_SRC = hexaPrint.c

# Default target to build both executables
all: $(BUBBLESORT_TARGET) $(HEXAPRINT_TARGET)

# Rule to build the bubblesort executable
$(BUBBLESORT_TARGET): $(BUBBLESORT_SRC)
	$(CC) $(CFLAGS) -o $(BUBBLESORT_TARGET) $(BUBBLESORT_SRC)

# Rule to build the hexaPrint executable
$(HEXAPRINT_TARGET): $(HEXAPRINT_SRC)
	$(CC) $(CFLAGS) -o $(HEXAPRINT_TARGET) $(HEXAPRINT_SRC)

# Rule to run the bubblesort program with default arguments
run_bubblesort: $(BUBBLESORT_TARGET)
	./$(BUBBLESORT_TARGET) 3 4 2 1

# Rule to run the hexaPrint program with a sample file
run_hexaprint: $(HEXAPRINT_TARGET)
	./$(HEXAPRINT_TARGET) exampleFile

# Rule to test hexaPrint program
test_hexaprint: $(HEXAPRINT_TARGET)
	@echo "Creating exampleFile with sample data..."
	@echo -n -e "\x63\x68\x65\x63\x6B\xAA\xDD\x4D\x79\x0C\x48\x65\x78" > exampleFile
	./$(HEXAPRINT_TARGET) exampleFile

# Rule to clean up the build
clean:
	rm -f $(BUBBLESORT_TARGET) $(HEXAPRINT_TARGET) exampleFile

# Phony targets
.PHONY: all run_bubblesort run_hexaprint test_hexaprint clean
