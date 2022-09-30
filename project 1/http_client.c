/*
 * CS 1652 Project 1 (client)
 * (c) Jack Lange, 2020
 * (c) Amy Babay, 2022
 * (c) Samuel Lasky, David Reidenbaugh
 * 
 * Computer Science Department
 * University of Pittsburgh
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFSIZE 1024

int readStatus(int bytesRecv, int pos, char* lineRead);
int readHeader(int bytesRecv, int pos, char* lineRead);

//our global variables
char* headers;
int headersSize = 0;

char version[200];
int code = 0;

int 
main(int argc, char ** argv) 
{

    char * server_name = NULL;
    int    server_port = -1;
    char * server_path = NULL;
    char * req_str     = NULL;

    int ret = 0;

    //non-global variables added by us
    struct hostent *hostIP;
    struct sockaddr_in remoteSockAddr;

    int bytesSent = 0;
    int totalBytesSent = 0;
    int bytesRecv = 0;
    int setSize = 0;

    char lineRead[BUFSIZE];


    fd_set readSet, writeSet, errorSet;

    /*parse args */
    if (argc != 4) {
        fprintf(stderr, "usage: http_client <hostname> <port> <path>\n");
        exit(-1);
    }

    server_name = argv[1];
    server_port = atoi(argv[2]);
    server_path = argv[3];
    
    /* Create HTTP request */
    ret = asprintf(&req_str, "GET %s HTTP/1.0\r\n\r\n", server_path);
    if (ret == -1) {
        fprintf(stderr, "Failed to allocate request string\n");
        exit(-1);
    }


    /* make socket */
    int remoteSock = socket(AF_INET, SOCK_STREAM, 0);
    if(remoteSock < 0){
        fprintf(stderr, "tcp_client: failed to create socket\n");
        exit(-1);
    }

    /* get host IP address  */
    /* Hint: use gethostbyname() */
    hostIP = gethostbyname(server_name);
    if(hostIP == NULL){
        fprintf(stderr, "tcp client: gethostbyname error\n"); 
        exit(-1);
    }

    /* set address */
    memset(&remoteSockAddr,0, sizeof(remoteSockAddr));
    remoteSockAddr.sin_family = AF_INET;
    remoteSockAddr.sin_port = htons(server_port);
    memcpy(&remoteSockAddr.sin_addr.s_addr, hostIP->h_addr, hostIP->h_length);

    /* connect to the server */
    if(connect(remoteSock, (struct sockaddr*)&remoteSockAddr, sizeof(remoteSockAddr) )< 0){
        fprintf(stderr, "tcp_client: could not connect to server\n");
        exit(-1);
    }


    /* send request message */
    while(totalBytesSent < ret){ //send the entire message, loop until we have sent all of the message  
        bytesSent = send(remoteSock, req_str+totalBytesSent, ret-totalBytesSent, 0);
            //retransmit the message from the char* starting from the byte whos place is equal to totalBytesSent
            //the length left to transmit is totalBytesSent less than the full length of the starting message 
        if(bytesSent < 0){ 
        fprintf(stderr, "tcp_client: send error\n"); 
	    close(remoteSock);
            exit(-1);
        }
        totalBytesSent += bytesSent;
    }

    

    /* wait for response (i.e. wait until socket can be read) */
    /* Hint: use select(), and ignore timeout for now. */
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);
    FD_SET(remoteSock, &readSet);
    setSize = select(remoteSock+1, &readSet, NULL, NULL, NULL);
    if(setSize <= 0){ //??? need this conditional, or would it just wait forever since no timeout
        fprintf(stderr, "tcp_client: socket was not read\n"); 
	close(remoteSock);
        exit(-1);
    }

	if(!FD_ISSET(remoteSock, &readSet)){
        fprintf(stderr, "tcp_client: socket not ready to read");
        close(remoteSock);
        exit(-1);
    }

	
    //malloc space for char pointers to store status line and header
    headers = malloc(BUFSIZE);
    if(headers == NULL){
	fprintf(stderr, "tcp_client: malloc error initialization\n");
	close(remoteSock);
	exit(-1);
    }

    //reset the buffer 
    memset(lineRead, 0, sizeof(lineRead));

    //keep track of position in the lineRead buffer
    int pos;
    
    //keep track of whether status and header have been found yet
    int headerFound = 0;
    int headerPrinted = 0;
    int messageError = 0;

    //search lineRead buffer for "\r\n" and "\r\n\r\n" (find status or header)
    char* match = NULL;
    

    //Read response from server
    while((bytesRecv = recv(remoteSock, lineRead, BUFSIZE-1, 0)) > 0){
	//reset position and match value (may not strictly necessary to reset match)
	pos = 0;
	match = NULL;

	//error receving if negative number returned
    	if(bytesRecv < 0){
        	fprintf(stderr, "tcp_client: recv error\n"); 
    		free(headers);
    		close(remoteSock);
    		exit(-1);
    	}

	
	//isolate headers in a string
	if(headerFound == 0){
		match = strstr(lineRead, "\r\n\r\n");
		pos = readHeader(bytesRecv, pos, lineRead);
		if(pos == -1){
				fprintf(stderr, "tcp_client: failure reading header\n");
    			free(headers);
    			close(remoteSock);
    			exit(-1);
		}
		if(match != NULL){
			//check status ok or not
    			sscanf(headers, "%s %d", version, &code);
			if(code != 200){
				messageError = 1;
			}
			headerFound = 1;
		}
	}


	//use two separate if's because both may need to read from same buffer
	//print out message 
	if(headerFound == 1){
		//print to standard out
		if(messageError == 0){
    			/* second read loop -- print out the rest of the response: real web content */
			for(int i = pos; i < bytesRecv; i++){
				printf("%c", lineRead[i]);

			}
		}
		//print to standard error (messageError == 1)
		else{ 
			if(headerPrinted == 0){
				fprintf(stderr, "%s", headers);
				headerPrinted = 1;
			}
			for(int i = pos; i < bytesRecv; i++){
				fprintf(stderr, "%c", lineRead[i]);
			}
		}
	}
	//reset the buffer
    	memset(lineRead, 0, sizeof(lineRead));
    }


    free(headers);
    close(remoteSock);
    if(messageError == 1){
	    exit(-1);
    }
    else{ //request is ok
    	return 0;
    }
}




//return pos to tell position in readResponse
//return -1 if error
int readHeader(int bytesRecv, int pos, char* lineRead){
    memset(headers, 0, BUFSIZE);
    int size = BUFSIZE; 
    for(int i = pos; i < bytesRecv; i++){
	//resize
	if(headersSize >= size-5){
		size += BUFSIZE;
		headers = realloc(headers, size);
		if(headers == NULL){
			fprintf(stderr, "tcp_client: malloc error header\n");
			return -1;
		}
	}
	pos = i;
	char currChar = lineRead[i];
	//check if at blank line, sequence -> (carriage, new line, carriage, newline)
	bool carriage1 = (currChar == '\r');
	bool newLine1 = (lineRead[i+1] == '\n');
	bool carriage2 = (lineRead[i+2] == '\r');
	bool newLine2 = (lineRead[i+3] == '\n');

	if(carriage1 && newLine1 && carriage2 && newLine2){
		//???should I read in the \r\n\r\n first
		headers[headersSize++] = currChar;
                headers[headersSize++] = lineRead[i+1];
                headers[headersSize++] = lineRead[i+2];
                headers[headersSize++] = lineRead[i+3];
		pos += 4;
		break;
	}
	else{
		headers[headersSize++] = currChar;
	}
    }
    return pos;
}
