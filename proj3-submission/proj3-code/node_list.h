/*
 * CS 1652 Project 3 
 * (c) Amy Babay, 2022
 * (c) <Student names here>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */

#ifndef __NODE_LIST_H__
#define __NODE_LIST_H__

#include <arpa/inet.h>

#define MAX_NODES 100

struct node {
    uint32_t           id;
    struct sockaddr_in addr;
    struct sockaddr_in ctrl_addr;
    struct node *      next_hop;
};

struct node_list {
    struct node *nodes[MAX_NODES];
    int          num_nodes;
};

/* Find and return node with given id.
 *     returns pointer to node if found successfully, NULL if not found */
struct node *get_node_from_id(struct node_list *list, uint32_t id);

/* Add node to node list.
 *     returns pointer to node if added successfully, NULL if list is full.
 *   Note that this functions creates a new node struct and copies the node
 *   param passed in into it */
struct node * add_node_to_list(struct node_list *list, struct node n);

#endif
