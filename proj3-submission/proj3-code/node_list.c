/*
 * CS 1652 Project 3 
 * (c) Amy Babay, 2022
 * (c) <Student names here>
 * 
 * Computer Science Department
 * University of Pittsburgh
 */

#include <stdlib.h>
#include "spu_alarm.h"
#include "node_list.h"

/* Find and return node with given id.
 *     returns pointer to node if found successfully, NULL if not found */
struct node *get_node_from_id(struct node_list *list, uint32_t id)
{
    int i;

    for (i = 0; i < list->num_nodes; i++)
    {
        if (list->nodes[i]->id == id) {
            return list->nodes[i];
        }
    }

    return NULL;
}

/* Add node to node list.
 *     returns pointer to node if added successfully, NULL if list is full.
 *   Note that this functions creates a new node struct and copies the node
 *   param passed in into it */
struct node * add_node_to_list(struct node_list *list, struct node n)
{
    if (list->num_nodes == MAX_NODES) {
        Alarm(DEBUG, "Node list full. Not adding new node\n");
        return NULL;
    }

    list->nodes[list->num_nodes] = calloc(1, sizeof(struct node));
    *(list->nodes[list->num_nodes]) = n;
    list->num_nodes++;

    return list->nodes[list->num_nodes - 1];
}
