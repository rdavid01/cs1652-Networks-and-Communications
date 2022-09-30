/*
 * CS 1652 Project 3 
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
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/errno.h>

#include <spu_alarm.h>
#include <spu_events.h>

#include "client_list.h"

/* Remove (and free) client with given control_sock.
 *     returns 0 if removed successfully, -1 if not found */
int remove_client_with_sock(struct client_list *list, int sock)
{
    int i;

    Alarm(DEBUG, "Removing client with sock %d\n", sock);
    for (i = 0; i < list->num_clients; i++)
    {
        if (list->clients[i]->control_sock == sock) {
            close(list->clients[i]->control_sock);
            close(list->clients[i]->data_sock);
            E_detach_fd(list->clients[i]->control_sock, READ_FD);
            E_detach_fd(list->clients[i]->data_sock, READ_FD);
            list->num_clients--;
            free(list->clients[i]);
            list->clients[i] = NULL;
            list->clients[i] = list->clients[list->num_clients]; /* swap in last element of list */
            return 0;
        }
    }

    return -1;
}

/* Find and return client with given data port.
 *     returns pointer to client if found successfully, NULL if not found */
struct client_conn *get_client_from_port(struct client_list *list, uint16_t port)
{
    int i;

    for (i = 0; i < list->num_clients; i++)
    {
        if (list->clients[i]->data_local_port == port) {
            return list->clients[i];
        }
    }

    return NULL;
}

/* Find and return client with given control_sock.
 *     returns pointer to client if found successfully, NULL if not found */
struct client_conn *get_client_from_sock(struct client_list *list, int sock)
{
    int i;

    for (i = 0; i < list->num_clients; i++)
    {
        if (list->clients[i]->control_sock == sock) {
            return list->clients[i];
        }
    }

    return NULL;
}

/* Add client to client list.
 *     returns pointer to client if added successfully, NULL if list is full.
 *   Note that this functions creates a new client struct and copies the c
 *   param passed in into it */
struct client_conn * add_client_to_list(struct client_list *list, struct client_conn c)
{
    if (list->num_clients == MAX_CLIENTS) {
        Alarm(DEBUG, "Client list full. Not adding new connection\n");
        return NULL;
    }

    list->clients[list->num_clients] = calloc(1, sizeof(struct client_conn));
    *(list->clients[list->num_clients]) = c;
    list->num_clients++;

    return list->clients[list->num_clients - 1];
}
