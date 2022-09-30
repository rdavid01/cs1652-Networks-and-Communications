# Detect OS
UNAME := $(shell uname)

# BASE_DIR is the top-level directory containing source code
BASE_DIR=.
# EXEC_DIR is the directory to put the executables in
EXEC_DIR=$(BASE_DIR)/bin

SRC_DIR=$(BASE_DIR)

INC=-I$(BASE_DIR)/libspread-util/include -I$(EXEC_DIR)/libspread-util/include

LIBSPREAD_UTIL=$(EXEC_DIR)/libspread-util/lib/libspread-util.a

# Special case since -lrt doesn't exist on OSX
ifeq ($(UNAME), Darwin)
LIBS=-ldl
else
LIBS=-ldl -lrt -lpthread -lm
endif

CC=gcc
CFLAGS=$(INC) -Wall -pedantic -g -D_GNU_SOURCE

all: $(LIBSPREAD_UTIL) overlay_node overlay_client

$(EXEC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(LIBSPREAD_UTIL):
	cd $(EXEC_DIR)/libspread-util; ../../libspread-util/configure; make

overlay_node: $(EXEC_DIR)/overlay_node.o $(EXEC_DIR)/client_list.o $(EXEC_DIR)/node_list.o $(EXEC_DIR)/edge_list.o
	$(CC) -o $(EXEC_DIR)/overlay_node $(EXEC_DIR)/overlay_node.o $(EXEC_DIR)/client_list.o $(EXEC_DIR)/node_list.o  $(EXEC_DIR)/edge_list.o $(LIBSPREAD_UTIL) $(LIBS)

overlay_client: $(EXEC_DIR)/overlay_client.o
	$(CC) -o $(EXEC_DIR)/overlay_client $(EXEC_DIR)/overlay_client.o $(LIBSPREAD_UTIL) $(LIBS)

clean:
	rm -f $(EXEC_DIR)/*.o

veryclean: clean
	rm -f $(EXEC_DIR)/overlay_node
	rm -f $(LIBSPREAD_UTIL)
