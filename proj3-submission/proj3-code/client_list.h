/*
 * CS 1652 Project 3 
 * (c) Amy Babay, 2022
 * (c) <Student names here>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */

#ifndef __CLIENT_LIST_H__
#define __CLIENT_LIST_H__

#define MAX_CLIENTS 100

struct client_conn {
    int control_sock; /* TCP socket used for "control" messages (i.e. set up / tear down) */
    int data_sock;    /* UDP socket used for data messages */
    uint16_t data_local_port; /* Port used for receiving data messages */
    uint16_t data_remote_port; /* Port to send data messages to */
    struct sockaddr_in data_remote_addr;
};

struct client_list {
    struct client_conn *clients[MAX_CLIENTS];
    int num_clients;
};

/* Remove (and free) client with given control_sock.
 *     returns 0 if removed successfully, -1 if not found */
int remove_client_with_sock(struct client_list *list, int sock);

/* Find and return client with given data port.
 *     returns pointer to client if found successfully, NULL if not found */
struct client_conn *get_client_from_port(struct client_list *list, uint16_t port);

/* Find and return client with given control_sock.
 *     returns pointer to client if found successfully, NULL if not found */
struct client_conn *get_client_from_sock(struct client_list *list, int sock);

/* Add client to client list.
 *     returns pointer to client if added successfully, NULL if list is full.
 *   Note that this functions creates a new client struct and copies the c
 *   param passed in into it */
struct client_conn * add_client_to_list(struct client_list *list, struct client_conn c);

#endif
