/*
 * CS 1652 Project 1 (server 2) 
 * (c) Jack Lange, 2020
 * (c) Amy Babay, 2022
 * (c) <Student names here>
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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define BUFSIZE 1024
#define FILENAMESIZE 100


static int 
handle_connection(int sock) 
{
 
    char * ok_response_f  = "HTTP/1.0 200 OK\r\n"         \
                            "Content-type: text/plain\r\n"	\
                            "Content-length: %d \r\n\r\n";
    
    char * notok_response = "HTTP/1.0 404 FILE NOT FOUND\r\n"	\
                            "Content-type: text/html\r\n\r\n"	\
                            "<html><body bgColor=black text=white>\n"	\
                            "<h2>404 FILE NOT FOUND</h2>\n"		\
                            "</body></html>\n";

    int bytesRecv = 0;
    int bytesSent = 0;

    char lineRead[BUFSIZE];
    char lineWrite[BUFSIZE];

    char method[10];
    char resource[BUFSIZE];
    char version[30];

    FILE * fileToGet = NULL;
    int currChar;

    int goodMessage = 0; //1 means send good message, 0 means send bad message

    int messageSize = 0;
    int totalBytesSent = 0;

    int fileSize = 0;
    

    /* first read loop -- get request and headers*/
    //read incoming message
    char request[BUFSIZE];
    int requestSize = 0;
    memset(lineRead, 0, sizeof(lineRead));
    memset(request, 0, sizeof(request));
    int endOfMessage = 0;
    //int pos = 0;
    while((bytesRecv = recv(sock, lineRead, BUFSIZE-1, 0)) > 0){
            //onlyreturn 0 if connection closed (socket closed)
            //need to check for end of message
        if(bytesRecv < 0){
               fprintf(stderr, "tcp_server: recv error\n");
	       close(sock);
	       return -1;
        }
        for(int i = 0; i < BUFSIZE; i++){

                char currChar = lineRead[i];
                //check if at blank line, sequence
			//use '\r\n' because that is what telnet request end with
                bool carriage1 = (currChar == '\r');
                bool newLine1 = (lineRead[i+1] == '\n');

                if(carriage1 && newLine1){
                        //store the "\r\n\r\n" sequence in the buffer
                        request[requestSize++] = currChar;
                        request[requestSize++] = lineRead[i+1];
                        request[requestSize++] = lineRead[i+2];
                        request[requestSize++] = lineRead[i+3];
                                //!!!NOTE: change resize value to be 4 less than buffer size, may be adding the entire terminating sequence
                                //!!!NOTE: could move storing the currChar to before the conditional, and then just check an handle for the one case
                        endOfMessage = 1;
                        break; //break out of for loop
                }
                else{
                        request[requestSize++] = currChar;
                }
        }
        if(endOfMessage == 1){
                break; //break out of while loop
        }
    }

    /* parse request to get file name */
    sscanf(lineRead, "%s %s %s", method, resource, version);

    /* Assumption: For this project you only need to handle GET requests and filenames that contain no spaces */
    messageSize = 0;
    totalBytesSent = 0;
    fileSize = 0;
    memset(lineWrite, 0, sizeof(lineWrite));
    //check if file exists
    if((access(resource, R_OK)) < 0){
        //file doesnt exist
        //set flag to send bad message
        goodMessage = 0;
        //store message status and header
        strcpy(lineWrite, notok_response);
        messageSize = strlen(lineWrite);
    }
    else{
        //file exists
        //set flag to send good message
        goodMessage = 1;
        //get size of file
        fileToGet = fopen(resource, "r");
        if(fileToGet == NULL){
                fprintf(stderr, "tcp_server, problem opening file");
		close(sock);
                return -1;
        }
        fseek(fileToGet, 0, SEEK_END);
        fileSize = ftell(fileToGet);
        fclose(fileToGet);
        //use sprintf() to fill in %d of ok_response_f with the file's size
        if((messageSize = sprintf(lineWrite, ok_response_f, fileSize)) < 0){
                fprintf(stderr, "tcp_server: error formatting response message");
		close(sock);
                return -1;
        }
    }
    //lineWrite holds status and headers
    //messageSize holds size (in bytes) of status and headers string

    //send header portion of message
    while(totalBytesSent < messageSize){
        bytesSent = send(sock, lineWrite+totalBytesSent, messageSize-totalBytesSent, 0);
        if(bytesSent <= 0){
                fprintf(stderr, "tcp_server: error sending respone\n");
		close(sock);
                return -1;
        }
        totalBytesSent += bytesSent;
    }


    /* open and read the file */
    /* send response */
    //if file exists, send its data to connection socket
    messageSize = 0;
    memset(lineWrite, 0, sizeof(lineWrite));
    if(goodMessage == 1){
        // read file
        fileToGet = fopen(resource, "r");
        fseek(fileToGet, 0, SEEK_SET);
        if(fileToGet == NULL){
                fprintf(stderr, "tcp_server, problem opening file");
		close(sock);
		return -1;
        }
        else{
                //read file
                //loop until find end of file and then break
                //need to send after reading end of file
                //so keep track and terminate loop only after sending end of file
                int endOfFile = 0;
                //reset currChar
                currChar = 0;
                while(!endOfFile){
                        if(currChar == EOF){
                                endOfFile = 1;
                        }
                        currChar = fgetc(fileToGet);
                        //send message if buffer full or at end of file
                        if(messageSize == sizeof(lineWrite)-1 || currChar == EOF){
                                if(currChar != EOF){
                                        lineWrite[messageSize++] = currChar;
                                }
                                //send buffer contents
                                //reset totalBytesSent before sending new buffer
                                totalBytesSent = 0;
                                while(totalBytesSent < messageSize){
                                        bytesSent = send(sock, lineWrite+totalBytesSent, messageSize-totalBytesSent, 0);
                                        if(bytesSent <= 0){
                                        	fprintf(stderr, "tcp_server: error sending response\n");
						close(sock);
                                                return -1;
                                        }
                                        totalBytesSent += bytesSent;
                                }
                                //reset size and buffer contents
                                messageSize = 0;
                                memset(lineWrite, 0, sizeof(lineWrite));
                        }
                        //add characters from file to buffer
                        else{
                                lineWrite[messageSize++] = currChar;
                        }

                }
        fclose(fileToGet);
        }
    }



    /* close socket and free space */
    close(sock); 
    return 0;
}



int
main(int argc, char ** argv)
{
    int server_port = -1;
    int ret         =  0;
    //int sock        = -1;

    int acceptSock, connectSock;
    struct sockaddr_in acceptSockAddr;

    fd_set master, readSet, writeSet, errorSet;
    int sockMax = 0;

    /* parse command line args */
    if (argc != 2) {
        fprintf(stderr, "usage: http_server1 port\n");
        exit(-1);
    }

    server_port = atoi(argv[1]);

    if (server_port < 1500) {
        fprintf(stderr, "Requested port(%d) must be above 1500\n", server_port);
        exit(-1);
    }
    
    /* initialize and make socket */
    acceptSock = socket(AF_INET, SOCK_STREAM, 0);
    if(acceptSock < 0){
        fprintf(stderr, "tcp_server: failed to create socket\n");
        exit(-1);
    }

    /* set server address */
    memset(&acceptSockAddr,0, sizeof(acceptSockAddr));
    acceptSockAddr.sin_family = AF_INET;
    acceptSockAddr.sin_port = htons(server_port); //server port is argv[1]
    acceptSockAddr.sin_addr.s_addr = INADDR_ANY;

    /* bind listening socket */
    int bindVal = bind(acceptSock, (struct sockaddr *)&acceptSockAddr, sizeof(acceptSockAddr));
    if(bindVal < 0){
        fprintf(stderr, "tcp_server: bind error\n");
        close(acceptSock);
        exit(-1);
    }

    /* start listening */
    int listenVal = listen(acceptSock, 20);
    if(listenVal < 0){
            fprintf(stderr, "tcp_server: listen error\n");
            close(acceptSock);
            exit(-1);
    }

    FD_ZERO(&master);
    FD_ZERO(&readSet);
    FD_ZERO(&writeSet);
    FD_ZERO(&errorSet);

    FD_SET(acceptSock, &master);
    sockMax = acceptSock;

    /* connection handling loop: wait to accept connection */
    while (1) {
    
        /* create read list */
	readSet = master;
        
        /* do a select() */
	if((select(sockMax+1, &readSet, NULL, NULL, NULL)) <= 0){
		fprintf(stderr, "tcp_server: select error\n");
		close(acceptSock);
		exit(-1);
	}

        /* process sockets that are ready:
         *     for the accept socket, add accepted connection to connections
         *     for a connection socket, handle the connection
         */
        for(int i = 0; i <= sockMax; i++){
	    if(FD_ISSET(i, &readSet)){
		//accept socket, accept new connection
		if(i == acceptSock){
			//accept connection
			connectSock = accept(acceptSock, NULL, NULL);
			if(connectSock < 0){
		                 fprintf(stderr, "tcp_server: accept error\n");
		                 close(acceptSock);
		                 exit(-1);
		        }
			FD_SET(connectSock, &master);
			if(connectSock > sockMax){
				sockMax = connectSock;
			}
		}
		//conection socket, handle the connection
		else{
        		ret = handle_connection(i);
			if(ret < 0){
				fprintf(stderr, "tcp_server: handling error\n");
				close(acceptSock);
				exit(-1);
			}

			//remove from master
			FD_CLR(i, &master);
		}

	    }
	}
    }
    close(acceptSock);
    return 0;
}
