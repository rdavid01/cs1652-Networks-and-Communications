/*
 * CS 1652 Project 3 
 * (c) Amy Babay, 2022
 * (c) David Reidenbaugh 
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

#include "packets.h"
#include "client_list.h"
#include "node_list.h"
#include "edge_list.h"

#define PRINT_DEBUG 1

#define MAX_CONF_LINE 1024
#define MAX_NODES     100
#define MAX_EDGES     500

enum mode {
    MODE_NONE,
    MODE_LINK_STATE,
    MODE_DISTANCE_VECTOR,
};

static uint32_t           My_IP      = 0;
static uint32_t           My_ID      = 0;
static uint16_t           My_Port    = 0;
static enum mode          Route_Mode = MODE_NONE;
static struct client_list Client_List;
static struct node_list   Node_List;
static struct edge_list   Edge_List;


int activeNeighbors[MAX_NODES];

int updateNum = 1; //keep track of what update # to send next (other nodes use to know if they have seen an update yet)
int updateNums[MAX_NODES];  //keep track of update number received from each node
int activeEdges[MAX_NODES][MAX_NODES]; //row is src, column is dst.  what edges are active or down (used by LS)

static int                My_Data_Sock    = 0;
static int                My_Control_Sock = 0;

int                       fwdTable[MAX_NODES];  //to send to node with id 'i', send to fwdTable[i]
int                       DVTable[MAX_NODES][MAX_NODES]; //distance vector (shortest route to a node) (used by DV)
int                       currRoute[MAX_NODES][MAX_NODES];//which node does node with id 'row' route through
							  //used by DV to handle infinite count problem


static const sp_time Data_Timeout = {1, 0};
//static const sp_time Lost_Con_Timeout = {3, 0}; //quicker timeouts, used for testing
static const sp_time Lost_Con_Timeout = {10, 0};

//neighbor_id: id of node want to send to
//update     : update number of current link state we are sharing (node will not forward message if they already saw it)
//firstSend  : if true, this is the node the advertisement originated from.  If false, it has been forwarded
//origin     : which node initially sent the message (could have been forwarded form another node, compare w/ update # of origin)
//msgUpdNum  : update number contained in the advertisement 
//dataRow[]  : if used, is for sharing list of active edges;
void send_link_state(int neighbor_id, int update, int firstSend, int origin, int msgUpdNum, int dataRow[MAX_NODES]){
    struct lsa_pkt lsaPkt;
    struct node        * neighbor;
    int                  bytes    = 0;
    int                  ret      = 0;
    lsaPkt.hdr.dst_id = neighbor_id;
    lsaPkt.hdr.src_id = My_ID;
    lsaPkt.hdr.type   = CTRL_LSA;

    neighbor = get_node_from_id(&Node_List, neighbor_id);

    //first time advertisement sent
    if(firstSend == 1){
        lsaPkt.origin = My_ID;
        lsaPkt.updateNum = update;
        for(int i=0; i < MAX_NODES; i++){
	    lsaPkt.updateRow[i] = activeEdges[My_ID][i];
	    if(fwdTable[i] == neighbor_id){
		lsaPkt.updateRow[i] = activeEdges[My_ID][i];
	    }
        }
    }
    //advertisement forwarded (reuse pkt fields from original message)
    else{
	lsaPkt.origin = origin;
	lsaPkt.updateNum = msgUpdNum;
	for(int i=0; i < MAX_NODES; i++){
	    lsaPkt.updateRow[i] = dataRow[i];
	    if(fwdTable[i] == neighbor_id){
	        lsaPkt.updateRow[i] = dataRow[i];
	    }
	}
    }

    //get the sockaddr of control socket
    	//couldn't add as struct field 
	//adding anything as struct field causes wierd problems where data structure contents are overwritten
    struct sockaddr_in ctrl_addr_ex = neighbor->addr;
    ctrl_addr_ex.sin_port = htons(ntohs(neighbor->addr.sin_port)+1);

    bytes = sizeof(lsaPkt);
    ret = sendto(My_Control_Sock,
		 &lsaPkt,
		 bytes,
		 0,
		 (struct sockaddr *)&ctrl_addr_ex,
                 sizeof(ctrl_addr_ex));
    if (ret < 0) {
        Alarm(PRINT, "Error sending link state advertisement to sock %d\n", My_Control_Sock);
        goto err;
    }

    return;
err:
    remove_client_with_sock(&Client_List, My_Control_Sock);
}

//neighbor_id: id of node to send to
void send_distance_vector(int neighbor_id){
    struct dv_pkt dvPkt;
    struct node        * neighbor;
    int                  bytes    = 0;
    int                  ret      = 0;
    dvPkt.hdr.dst_id = neighbor_id;
    dvPkt.hdr.src_id = My_ID;
    dvPkt.hdr.type   = CTRL_DV;

    neighbor = get_node_from_id(&Node_List, neighbor_id);

    //share distance vector
    for(int i=0; i < MAX_NODES; i++){
	dvPkt.DVRow[i] = DVTable[My_ID][i]; 
	dvPkt.fwdRow[i] = fwdTable[i];
    }

    struct sockaddr_in ctrl_addr_ex = neighbor->addr;
    ctrl_addr_ex.sin_port = htons(ntohs(neighbor->addr.sin_port)+1);
    
    bytes = sizeof(dvPkt);
    ret = sendto(My_Control_Sock,
		 &dvPkt,
		 bytes,
		 0,
		 (struct sockaddr *)&ctrl_addr_ex,
                 sizeof(ctrl_addr_ex));
    if (ret < 0) {
        Alarm(PRINT, "Error sending distance vector to sock %d\n", My_Control_Sock);
        goto err;
    }


    return;
err:
    remove_client_with_sock(&Client_List, My_Control_Sock);

}

//for LS route calculation
//startingId: which node to start the dijkstras from (in this program, always My_ID)
//forward   : whether or not to send LS advertisement (don't forward to neighbors if you have already seen) 
//update    : whether or not to increment updateNum (only do if you are the original sender)
//msgOrigin : which node originally sent this advertisement
//dataRow[] : passing along activeEdges known
void myDijkstras(int startingId, int forward, int update, int msgOrigin, int msgUpdNum, int dataRow[MAX_NODES]){
    int nodeCount = Node_List.num_nodes;
    int edgeCount = Edge_List.num_edges;
    int visitedCount = 0;
    //use a node's id to index into visited and distance
    int visited[MAX_NODES]; //if the node with this position in Node_List has been visited
    int distance[MAX_NODES];//the distance from the node with startingId to the node with this position in Node_List

    //initialize arrays
    for(int i=0; i < MAX_NODES; i++){
	visited[i]  = 0;
	distance[i] = INT_MAX;
	fwdTable[i] = INT_MAX;
    }
    //for node with startingId, set distance to 0 and visited to 1 (meaning true)
    visited[startingId] = 1;
    distance[startingId] = 0;
    fwdTable[startingId] = startingId; 
    visitedCount++;

    //look for next node to visit until all nodes visited
    while(visitedCount < nodeCount){
	//loop through edges
	for(int i=0; i < edgeCount; i++){
	    int srcEdgeId = Edge_List.edges[i]->src_id;
	    int dstEdgeId = Edge_List.edges[i]->dst_id;
	    int edgeCost  = Edge_List.edges[i]->cost;
	    //if edge's src is visited
	    int visitable = (visited[srcEdgeId] == 1) && (visited[dstEdgeId] == 0);
	    int available = activeEdges[srcEdgeId][dstEdgeId];
	    //need to check for each node can be reached
	    if(visitable && available){
		int pathCost = distance[srcEdgeId] + edgeCost;
		//if found shorter distance to a node
	        if(distance[dstEdgeId] > pathCost){
		    distance[dstEdgeId] = pathCost;
		    if(srcEdgeId == startingId){
			fwdTable[dstEdgeId] = dstEdgeId;
		    }
		    else{
			fwdTable[dstEdgeId] = fwdTable[srcEdgeId];
		    }
		}
	    }	
	}
	//find shortest path
	int currShortest = INT_MAX;
	int currShortestIndex = -1;
	for(int i=0; i < MAX_NODES; i++){
	    if((distance[i] < currShortest) && (visited[i] == 0)){
		currShortest = distance[i];
		currShortestIndex = i;
	    }
	}
	visited[currShortestIndex] = 1;
	visitedCount++;

    }

    if(forward == 1){
        for(int i=0; i < Edge_List.num_edges; i++){
            int srcEdgeId = Edge_List.edges[i]->src_id;
            int dstEdgeId = Edge_List.edges[i]->dst_id;
            if(srcEdgeId == My_ID && activeEdges[srcEdgeId][dstEdgeId] == 1){
	        if(update == 1){
	           //first send, disregard origin
                   send_link_state(dstEdgeId, updateNum, 1, 0, 0, updateNums);
		}
		else{
	          //else, forwarding from message origin, include message origin
		   send_link_state(dstEdgeId, updateNum, 0, msgOrigin, msgUpdNum, dataRow);
		}
            }
        }   
	//do this after because want to send to all neighbors, but only want to increment once
        if(update == 1){
	    updateNum++;
	    updateNums[My_ID] = updateNum;
	}
    }
}


//for DV route calculation
//startingId  : which node to start compuation for
//tableUpdated: if we received a DV advertisement, has it already prompted a change in our table
void bellman(int startingId, int tableUpdated){
    int changeOccurred = 0;
    int edgeCount = Edge_List.num_edges;

    for(int i=0; i < MAX_NODES; i++){
	int row = fwdTable[i];
	int column = i;
	if(row < MAX_NODES){
	    int lookAt = DVTable[row][column];
	    if(lookAt == INT_MAX){
	        for(int j=0; j < MAX_NODES; j++){
			DVTable[j][column] = INT_MAX;
		}
		fwdTable[i] = INT_MAX;
	    }
	}
    }

    //build neighbors list and set some initial costs
    int neighbors[MAX_NODES];
    int neighborsLen = 0;
    for(int i=0; i < Edge_List.num_edges; i++){
	if(Edge_List.edges[i]->src_id == My_ID){
	    int dstId = Edge_List.edges[i]->dst_id;
	    neighbors[neighborsLen++] = dstId;
	    if(DVTable[My_ID][dstId] == INT_MAX){
		for(int j=0; j < MAX_NODES; j++){
		    DVTable[dstId][j] = INT_MAX;
		    if(fwdTable[j] == dstId){
			fwdTable[j] = INT_MAX;
			DVTable[My_ID][j] = INT_MAX;
		    }
		}
	    }
	}
    }

    int currEst      = 0;
    int dirCost      = 0;
    int neighborCost = 0;
    int lcp          = 0; //least cost path
    struct edge * e = NULL;
    //look at each column in My_ID's row of the distance vector
    for(int i=0; i < MAX_NODES; i++){
	if(i != My_ID){
	    currEst = DVTable[My_ID][i];
	    //look at each neighbor's cost to that node to see if a shorter path available
	    int foundPath = 0;
	    for(int j = 0; j < neighborsLen; j++){
 		e = get_edge(&Edge_List, My_ID, neighbors[j]);
		//dirCost should be direct cost along link, not shortest cost from DVTable
		dirCost = e->cost;
		neighborCost = DVTable[ neighbors[j] ][i];
		int routable = (currRoute[neighbors[j]][i] != My_ID);
		if(dirCost != INT_MAX && neighborCost != INT_MAX && routable){//if cost is not INT_MAX (infinity)
		    foundPath = 1;
		    lcp = dirCost + neighborCost;
		    if((lcp < currEst)){ //see if cost is less
		        DVTable[My_ID][i] = lcp;
			fwdTable[i] = neighbors[j];
			changeOccurred = 1;
		    }
		    
		}
	    } 
	    if(foundPath == 0){
		DVTable[My_ID][i] = INT_MAX;
		fwdTable[i] = INT_MAX;
	    }
	}
    }

    // set costs to my neighbors if appropriate
    for(int i=0; i < edgeCount; i++){
        int srcEdgeId = Edge_List.edges[i]->src_id;
	int dstEdgeId = Edge_List.edges[i]->dst_id;
	int cost      = Edge_List.edges[i]->cost;
	if(srcEdgeId == startingId){
	    if(activeNeighbors[dstEdgeId] == 1){
	        //if neighbor active
		if(cost < DVTable[srcEdgeId][dstEdgeId]){
	    	    DVTable[srcEdgeId][dstEdgeId] = cost;
		    fwdTable[dstEdgeId] = dstEdgeId;
		}
	    }
	    else{
	        //else link to neighbor is down, cost should be INT_MAX
		DVTable[srcEdgeId][dstEdgeId] = INT_MAX;
		fwdTable[dstEdgeId] = INT_MAX;
	    }
	}	    
    }

    if(changeOccurred == 1 || tableUpdated == 1){
	for(int i=0; i < neighborsLen; i++){
		send_distance_vector(neighbors[i]);
	}		
    }
}



//link from My_ID to node with id <neighbor_id> failed
void link_failed(int neighbor_id, void * unused){

    activeNeighbors[neighbor_id] = 0;

    if (Route_Mode == MODE_LINK_STATE) {
	//recompute dijkstras and advertise new fwdTable
        activeEdges[My_ID][neighbor_id] = 0;
	activeEdges[neighbor_id][My_ID] = 0;

	//send update
        myDijkstras(My_ID, 1, 1, 0, 0, updateNums);

    } else {
	//Route_Mode == MODE_DISTANCE_VECTOR
	//recompute bellman and advertise fwdTable
	
    	DVTable[My_ID][neighbor_id] = INT_MAX;
	for(int i=0; i < MAX_NODES; i++){
	    if(fwdTable[i] == neighbor_id){
		DVTable[My_ID][i] = INT_MAX;
	    }
	    DVTable[i][neighbor_id] = INT_MAX;
	}

        bellman(My_ID, 1);
    }

}

void send_heartbeat(int neighbor_id, void * unused){
    struct heartbeat_pkt heartPkt;
    struct node        * n;
    int                  bytes    = 0;
    int                  ret      = 0;
    heartPkt.hdr.dst_id = neighbor_id;
    heartPkt.hdr.src_id = My_ID;
    heartPkt.hdr.type   = CTRL_HEARTBEAT;

    n = get_node_from_id(&Node_List, neighbor_id);
    
    struct sockaddr_in ctrl_addr_ex = n->addr;
    ctrl_addr_ex.sin_port = htons(ntohs(n->addr.sin_port)+1);

    bytes = sizeof(heartPkt);
    ret = sendto(My_Control_Sock,
		 &heartPkt,
		 bytes,
		 0,
		 (struct sockaddr *)&ctrl_addr_ex,
                 sizeof(n->ctrl_addr));
    if (ret < 0) {
        Alarm(PRINT, "Error sending heartbeat to sock %d\n", My_Control_Sock);
        goto err;
    }

    //start timer to send a heartbeat packet every second
    E_queue(send_heartbeat, neighbor_id, &heartPkt, Data_Timeout);

    return;
err:
    remove_client_with_sock(&Client_List, My_Control_Sock);
}

/* Forward the packet to the next-hop node based on forwarding table */
void forward_data(struct data_pkt *pkt)
{

    Alarm(DEBUG, "overlay_node: forwarding data to overlay node %u, client port "
                 "%u\n", pkt->hdr.dst_id, pkt->hdr.dst_port);
    /*
     * Students fill in! Do forwarding table lookup, update path information in
     * header (see deliver_locally for an example), and send packet to next hop
     * */

    int path_len = 0;
    int bytes = 0;
    int ret = -1;
    int nextHopId = 0;
    int dstId     = 0;
    struct client_conn *c = NULL;
    struct node * neighbor = NULL;

    //use forwarding table to find id of next node to send to
    dstId    = pkt->hdr.dst_id;
    nextHopId = fwdTable[dstId];
    neighbor = get_node_from_id(&Node_List, nextHopId);

    if(nextHopId == INT_MAX){
	Alarm(PRINT, "Error, sending to node when link is down. Preventing Send.\n");
	return;
    }

    path_len = pkt->hdr.path_len;
    if (path_len < MAX_PATH) {
        pkt->hdr.path[path_len] = My_ID;
        pkt->hdr.path_len++;
    }

    /* Send data to client */
    bytes = sizeof(struct data_pkt);
    ret = sendto(My_Data_Sock,
		 pkt, 
		 bytes, 
		 0,
                 (struct sockaddr *)&neighbor->addr,
                 sizeof(neighbor->addr));
    if (ret < 0) {
        Alarm(PRINT, "Error sending to client with sock %d %d:%d\n",
              c->data_sock, c->data_local_port, c->data_remote_port);
        goto err;
    }

    return;

err:
    remove_client_with_sock(&Client_List, c->control_sock);
}

/* Deliver packet to one of my local clients */
void deliver_locally(struct data_pkt *pkt)
{
    int path_len = 0;
    int bytes = 0;
    int ret = -1;
    struct client_conn *c = get_client_from_port(&Client_List, pkt->hdr.dst_port);

    /* Check whether we have a local client with this port to deliver to. If
     * not, nothing to do */
    if (c == NULL) {
        Alarm(PRINT, "overlay_node: received data for client that does not "
                     "exist! overlay node %d : client port %u\n",
                     pkt->hdr.dst_id, pkt->hdr.dst_port);
        return;
    }

    Alarm(DEBUG, "overlay_node: Delivering data locally to client with local "
                 "port %d\n", c->data_local_port);

    /* stamp packet so we can see the path taken */
    path_len = pkt->hdr.path_len;
    if (path_len < MAX_PATH) {
        pkt->hdr.path[path_len] = My_ID;
        pkt->hdr.path_len++;
    }

    /* Send data to client */
    bytes = sizeof(struct data_pkt) - MAX_PAYLOAD_SIZE + pkt->hdr.data_len;
    ret = sendto(c->data_sock, pkt, bytes, 0,
                 (struct sockaddr *)&c->data_remote_addr,
                 sizeof(c->data_remote_addr));
    if (ret < 0) {
        Alarm(PRINT, "Error sending to client with sock %d %d:%d\n",
              c->data_sock, c->data_local_port, c->data_remote_port);
        goto err;
    }

    return;

err:
    remove_client_with_sock(&Client_List, c->control_sock);
}

/* Handle incoming data message from another overlay node. Check whether we
 * need to deliver locally to a connected client, or forward to the next hop
 * overlay node */
void handle_overlay_data(int sock, int code, void *data)
{
    int bytes;
    struct data_pkt pkt;
    struct sockaddr_in recv_addr;
    socklen_t fromlen;

    Alarm(DEBUG, "overlay_node: received overlay data msg!\n");

    fromlen = sizeof(recv_addr);
    bytes = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&recv_addr,
                     &fromlen);
    if (bytes < 0) {
        Alarm(EXIT, "overlay node: Error receiving overlay data: %s\n",
              strerror(errno));
    }

    /* If there is data to forward, find next hop and forward it */
    if (pkt.hdr.data_len > 0) {
        char tmp_payload[MAX_PAYLOAD_SIZE+1];
        memcpy(tmp_payload, pkt.payload, pkt.hdr.data_len);
        tmp_payload[pkt.hdr.data_len] = '\0';
        Alarm(DEBUG, "Got forwarded data packet of %d bytes: %s\n",
              pkt.hdr.data_len, tmp_payload);

        if (pkt.hdr.dst_id == My_ID) {
            deliver_locally(&pkt);
        } else {
            forward_data(&pkt);
        }
    }
}

/* Respond to heartbeat message by sending heartbeat echo */
void handle_heartbeat(struct heartbeat_pkt *pkt)
{
    if (pkt->hdr.type != CTRL_HEARTBEAT) {
        Alarm(PRINT, "Error: non-heartbeat msg in handle_heartbeat\n");
        return;
    }

    Alarm(DEBUG, "Got heartbeat from %d\n", pkt->hdr.src_id);

     /* Students fill in! */
    struct node * n = NULL;
    struct heartbeat_echo_pkt echoPkt;
    int bytes = 0;
    int ret   = 0;

    echoPkt.hdr.src_id = My_ID;
    echoPkt.hdr.dst_id = pkt->hdr.src_id;
    echoPkt.hdr.type   = CTRL_HEARTBEAT_ECHO;


    n = get_node_from_id(&Node_List, pkt->hdr.src_id);
    
    struct sockaddr_in ctrl_addr_ex = n->addr;
    ctrl_addr_ex.sin_port = htons(ntohs(n->addr.sin_port)+1);

    bytes = sizeof(echoPkt);
    ret = sendto(My_Control_Sock,
		 &echoPkt,
		 bytes,
		 0,
		 (struct sockaddr *)&ctrl_addr_ex,
                 sizeof(n->ctrl_addr));
    if (ret < 0) {
        Alarm(PRINT, "Error sending heartbeat to sock %d\n", My_Control_Sock);
        goto err;
    }
    return;
err:
    remove_client_with_sock(&Client_List, My_Control_Sock);
}

/* Handle heartbeat echo. This indicates that the link is alive, so update our
 * link weights and send update if we previously thought this link was down.
 * Push forward timer for considering the link dead */
void handle_heartbeat_echo(struct heartbeat_echo_pkt *pkt)
{
    if (pkt->hdr.type != CTRL_HEARTBEAT_ECHO) {
        Alarm(PRINT, "Error: non-heartbeat_echo msg in "
                     "handle_heartbeat_echo\n");
        return;
    }

    Alarm(DEBUG, "Got heartbeat_echo from %d\n", pkt->hdr.src_id);

     /* Students fill in! */
    int oldActiveStatus = activeNeighbors[pkt->hdr.src_id];
    activeNeighbors[pkt->hdr.src_id] = 1;

    //update link weights if thought node was down
    if(oldActiveStatus == 0){
    	if(Route_Mode == MODE_LINK_STATE){
            activeEdges[My_ID][pkt->hdr.src_id] = 1;
	    activeEdges[pkt->hdr.src_id][My_ID] = 1;
	    //send update
	    myDijkstras(My_ID, 1, 1, 0, 0, updateNums);
        }
        else{
	    bellman(My_ID, 0);
    	}
    }
    
    //push timer forward for considering link dead
    E_queue(link_failed, pkt->hdr.src_id, &My_ID, Lost_Con_Timeout);


}

/* Process received link state advertisement */
void handle_lsa(struct lsa_pkt *pkt)
{
    if (pkt->hdr.type != CTRL_LSA) {
        Alarm(PRINT, "Error: non-lsa msg in handle_lsa\n");
        return;
    }

    if (Route_Mode != MODE_LINK_STATE) {
        Alarm(PRINT, "Error: LSA msg but not in link state routing mode\n");
    }

    Alarm(DEBUG, "Got lsa from %d\n", pkt->hdr.src_id);

     /* Students fill in! */
    //received notification about link weight change/availability
    if(updateNums[pkt->origin] < pkt->updateNum){ //don'f flood if already received this update number 	
	//update updates array
	updateNums[pkt->origin] = pkt->updateNum; //shouldn't flood further if already received
	//update activeEdges
	for(int i=0; i < MAX_NODES; i++){
	    activeEdges[pkt->origin][i] = pkt->updateRow[i];
	    activeEdges[i][pkt->origin] = pkt->updateRow[i];
	    //reset updateNums[] if node is offline
	    if(pkt->updateRow[i] == 0){
		updateNums[i] = 0;
	    }
	}
	//dont update updateNum because just forwarding form origin, not sending
        //recompute dijkstras
	//forward update
	myDijkstras(My_ID, 1, 0, pkt->origin, pkt->updateNum, pkt->updateRow);
    }
}

/* Process received distance vector update */
void handle_dv(struct dv_pkt *pkt)
{
    if (pkt->hdr.type != CTRL_DV) {
        Alarm(PRINT, "Error: non-dv msg in handle_dv\n");
        return;
    }

    if (Route_Mode != MODE_DISTANCE_VECTOR) {
        Alarm(PRINT, "Error: Distance Vector Update msg but not in distance "
                     "vector routing mode\n");
    }

    Alarm(DEBUG, "Got dv from %d\n", pkt->hdr.src_id);

     /* Students fill in! */
    activeNeighbors[pkt->hdr.src_id] = 1;

    //received FT broadcast from
    int tableUpdated = 0;
    //fill in/ adjust this node's dv table based on what received
    for(int i=0; i < MAX_NODES; i++){
	if(DVTable[pkt->hdr.src_id][i] != pkt->DVRow[i]){
	    tableUpdated = 1;
	}
	DVTable[pkt->hdr.src_id][i] = pkt->DVRow[i];
	currRoute[pkt->hdr.src_id][i] = pkt->fwdRow[i];
    }

    bellman(My_ID, tableUpdated);
}

/* Process received overlay control message. Identify message type and call the
 * relevant "handle" function */
void handle_overlay_ctrl(int sock, int code, void *data)
{
    char buf[MAX_CTRL_SIZE];
    struct sockaddr_in recv_addr;
    socklen_t fromlen;
    struct ctrl_hdr * hdr = NULL;
    int bytes = 0;

    Alarm(DEBUG, "overlay_node: received overlay control msg!\n");

    fromlen = sizeof(recv_addr);
    bytes = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&recv_addr,
                     &fromlen);
    if (bytes < 0) {
        Alarm(EXIT, "overlay node: Error receiving ctrl message: %s\n",
              strerror(errno));
    }
    hdr = (struct ctrl_hdr *)buf;

    /* sanity check */
    if (hdr->dst_id != My_ID) {
        Alarm(PRINT, "overlay_node: Error: got ctrl msg with invalid dst_id: "
              "%d\n", hdr->dst_id);
    }

    if (hdr->type == CTRL_HEARTBEAT) {
        /* handle heartbeat */
        handle_heartbeat((struct heartbeat_pkt *)buf);
    } else if (hdr->type == CTRL_HEARTBEAT_ECHO) {
        /* handle heartbeat echo */
        handle_heartbeat_echo((struct heartbeat_echo_pkt *)buf);
    } else if (hdr->type == CTRL_LSA) {
        /* handle link state update */
        handle_lsa((struct lsa_pkt *)buf);
    } else if (hdr->type == CTRL_DV) {
        /* handle distance vector update */
        handle_dv((struct dv_pkt *)buf);
    }
}

void handle_client_data(int sock, int unused, void *data)
{
    int ret, bytes;
    struct data_pkt pkt;
    struct sockaddr_in recv_addr;
    socklen_t fromlen;
    struct client_conn *c;

    Alarm(DEBUG, "Handle client data\n");
    
    c = (struct client_conn *) data;
    if (sock != c->data_sock) {
        Alarm(EXIT, "Bad state! sock %d != data sock\n", sock, c->data_sock);
    }

    fromlen = sizeof(recv_addr);
    bytes = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&recv_addr,
                     &fromlen);
    if (bytes < 0) {
        Alarm(PRINT, "overlay node: Error receiving from client: %s\n",
              strerror(errno));
        goto err;
    }

    /* Special case: initial data packet from this client. Use it to set the
     * source port, then ack it */
    if (c->data_remote_port == 0) {
        c->data_remote_addr = recv_addr;
        c->data_remote_port = ntohs(recv_addr.sin_port);
        Alarm(DEBUG, "Got initial data msg from client with sock %d local port "
                     "%u remote port %u\n", sock, c->data_local_port,
                     c->data_remote_port);

        /* echo pkt back to acknowledge */
        ret = sendto(c->data_sock, &pkt, bytes, 0,
                     (struct sockaddr *)&c->data_remote_addr,
                     sizeof(c->data_remote_addr));
        if (ret < 0) {
            Alarm(PRINT, "Error sending to client with sock %d %d:%d\n", sock,
                  c->data_local_port, c->data_remote_port);
            goto err;
        }
    }

    /* If there is data to forward, find next hop and forward it */
    if (pkt.hdr.data_len > 0) {
        char tmp_payload[MAX_PAYLOAD_SIZE+1];
        memcpy(tmp_payload, pkt.payload, pkt.hdr.data_len);
        tmp_payload[pkt.hdr.data_len] = '\0';
        Alarm(DEBUG, "Got data packet of %d bytes: %s\n", pkt.hdr.data_len, tmp_payload);

        /* Set up header with my info */
        pkt.hdr.src_id = My_ID;
        pkt.hdr.src_port = c->data_local_port;

        /* Deliver / Forward */
        if (pkt.hdr.dst_id == My_ID) {
            deliver_locally(&pkt);
        } else {
            forward_data(&pkt);
        }
    }

    return;

err:
    remove_client_with_sock(&Client_List, c->control_sock);
    
}

void handle_client_ctrl_msg(int sock, int unused, void *data)
{
    int bytes_read = 0;
    int bytes_sent = 0;
    int bytes_expected = sizeof(struct conn_req_pkt);
    struct conn_req_pkt rcv_req;
    struct conn_ack_pkt ack;
    int ret = -1;
    int ret_code = 0;
    char * err_str = "client closed connection";
    struct sockaddr_in saddr;
    struct client_conn *c;

    Alarm(DEBUG, "Client ctrl message, sock %d\n", sock);

    /* Get client info */
    c = (struct client_conn *) data;
    if (sock != c->control_sock) {
        Alarm(EXIT, "Bad state! sock %d != data sock\n", sock, c->control_sock);
    }

    if (c == NULL) {
        Alarm(PRINT, "Failed to find client with sock %d\n", sock);
        ret_code = -1;
        goto end;
    }

    /* Read message from client */
    while (bytes_read < bytes_expected &&
           (ret = recv(sock, ((char *)&rcv_req)+bytes_read,
                       sizeof(rcv_req)-bytes_read, 0)) > 0) {
        bytes_read += ret;
    }
    if (ret <= 0) {
        if (ret < 0) err_str = strerror(errno);
        Alarm(PRINT, "Recv returned %d; Removing client with control sock %d: "
                     "%s\n", ret, sock, err_str);
        ret_code = -1;
        goto end;
    }

    if (c->data_local_port != 0) {
        Alarm(PRINT, "Received req from already connected client with sock "
                     "%d\n", sock);
        ret_code = -1;
        goto end;
    }

    /* Set up UDP socket requested for this client */
    if ((c->data_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(PRINT, "overlay_node: client UDP socket error: %s\n", strerror(errno));
        ret_code = -1;
        goto send_resp;
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(rcv_req.port);

    /* bind UDP socket */
    if (bind(c->data_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(PRINT, "overlay_node: client UDP bind error: %s\n", strerror(errno));
        ret_code = -1;
        goto send_resp;
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(c->data_sock, READ_FD, handle_client_data, 0, c, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(PRINT, "Failed to register client UDP sock in event handling system\n");
        ret_code = -1;
        goto send_resp;
    }

send_resp:
    /* Send response */
    if (ret_code == 0) { /* all worked correctly */
        c->data_local_port = rcv_req.port;
        ack.id = My_ID;
    } else {
        ack.id = 0;
    }
    bytes_expected = sizeof(ack);
    Alarm(DEBUG, "Sending response to client with control sock %d, UDP port "
                 "%d\n", sock, c->data_local_port);
    while (bytes_sent < bytes_expected) {
        ret = send(sock, ((char *)&ack)+bytes_sent, sizeof(ack)-bytes_sent, 0);
        if (ret < 0) {
            Alarm(PRINT, "Send error for client with sock %d (removing...): "
                         "%s\n", sock, strerror(ret));
            ret_code = -1;
            goto end;
        }
        bytes_sent += ret;
    }

end:
    if (ret_code != 0 && c != NULL) remove_client_with_sock(&Client_List, sock);
}

void handle_client_conn(int sock, int unused, void *data)
{
    int conn_sock;
    struct client_conn new_conn;
    struct client_conn *ret_conn;
    int ret;

    Alarm(DEBUG, "Handle client connection\n");

    /* Accept the connection */
    conn_sock = accept(sock, NULL, NULL);
    if (conn_sock < 0) {
        Alarm(PRINT, "accept error: %s\n", strerror(errno));
        goto err;
    }

    /* Set up the connection struct for this new client */
    new_conn.control_sock     = conn_sock;
    new_conn.data_sock        = -1;
    new_conn.data_local_port  = 0;
    new_conn.data_remote_port = 0;
    ret_conn = add_client_to_list(&Client_List, new_conn);
    if (ret_conn == NULL) {
        goto err;
    }

    /* Register the control socket for this client */
    ret = E_attach_fd(new_conn.control_sock, READ_FD, handle_client_ctrl_msg,
                      0, ret_conn, MEDIUM_PRIORITY);
    if (ret < 0) {
        goto err;
    }

    return;

err:
    if (conn_sock >= 0) close(conn_sock);
}

void init_overlay_data_sock(int port)
{
    int sock = -1;
    int ret = -1;
    struct sockaddr_in saddr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: data socket error: %s\n", strerror(errno));
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);

    /* bind listening socket */
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(EXIT, "overlay_node: data bind error: %s\n", strerror(errno));
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(sock, READ_FD, handle_overlay_data, 0, NULL, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register overlay data sock in event handling system\n");
    }

    My_Data_Sock = sock;
}

void init_overlay_ctrl_sock(int port)
{
    int sock = -1;
    int ret = -1;
    struct sockaddr_in saddr;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_node: ctrl socket error: %s\n", strerror(errno));
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(port);

    /* bind listening socket */
    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(EXIT, "overlay_node: ctrl bind error: %s\n", strerror(errno));
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(sock, READ_FD, handle_overlay_ctrl, 0, NULL, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register overlay ctrl sock in event handling system\n");
    }

    My_Control_Sock = sock;
}

void init_client_sock(int client_port)
{
    int client_sock = -1;
    int ret = -1;
    struct sockaddr_in saddr;

    if ((client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        Alarm(EXIT, "overlay_node: client socket error: %s\n", strerror(errno));
    }

    /* set server address */
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(client_port);

    /* bind listening socket */
    if (bind(client_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        Alarm(EXIT, "overlay_node: client bind error: %s\n", strerror(errno));
    }

    /* start listening */
    if (listen(client_sock, 32) < 0) {
        Alarm(EXIT, "overlay_node: client bind error: %s\n", strerror(errno));
        exit(-1);
    }

    /* Register socket with event handling system */
    ret = E_attach_fd(client_sock, READ_FD, handle_client_conn, 0, NULL, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register client sock in event handling system\n");
    }

}


void init_link_state()
{
    /* Students fill in */
    Alarm(DEBUG, "init link state\n");

    void * unused = NULL;

    for(int i=0; i < MAX_NODES; i++){
	updateNums[i] = 0;
	activeNeighbors[i] = 1;
	for(int j=0; j < MAX_NODES; j++){
	    activeEdges[i][j] = 1;
	}
    }

    //build forwarding table using dijsktras to find least cost paths to all nodes
    //dont forward at all
    myDijkstras(My_ID, 0, 0, 0, 0, updateNums);

    //send heartbeats to all neighbors
    for(int i=0; i<Edge_List.num_edges; i++){
	int srcId = Edge_List.edges[i]->src_id;
	int dstId = Edge_List.edges[i]->dst_id;
	if(srcId == My_ID){
	    //send heartbeat to all neighbors
    	    send_heartbeat(dstId, unused); 

    	    //set a timer to declare link failure if no heartbeat echo in 10 seconds
    	    E_queue(link_failed, dstId, &My_ID, Lost_Con_Timeout);
	}
    }
}

void initBellman(int startingId){
    int edgeCount = Edge_List.num_edges;
    int vector [MAX_NODES][MAX_NODES];
    int tempFT [MAX_NODES];

    for(int i=0; i < MAX_NODES; i++){
        for(int j=0; j < MAX_NODES; j++){
	    vector[i][j] = INT_MAX;
	}
	tempFT[i] = INT_MAX;
    }

    //get the neighbors of the node
    for(int i=0; i < edgeCount; i++){
        int srcEdgeId = Edge_List.edges[i]->src_id;
	int dstEdgeId = Edge_List.edges[i]->dst_id;
	int cost      = Edge_List.edges[i]->cost;
	if(srcEdgeId == startingId){
	    vector[srcEdgeId][dstEdgeId] = cost;
	    tempFT[dstEdgeId] = dstEdgeId;
	}	    
    }
    vector[My_ID][My_ID] = 0;
    tempFT[My_ID]        = My_ID;

    for(int i=0; i < MAX_NODES; i++){
	for(int j=0; j < MAX_NODES; j++){
	    DVTable[i][j] = vector[i][j];//copy vector into DVtable
	}
	fwdTable[i] = tempFT[i];
    }
}


void init_distance_vector()
{
    /* Students fill in */
    Alarm(DEBUG, "init distance vector\n");

    void   *unused = NULL;

    for(int i=0; i < MAX_NODES; i++){
	updateNums[i] = 0;
	activeNeighbors[i] = 1;
	for(int j=0; j< MAX_NODES; j++){
	    currRoute[i][j] = 0;
	}
    }

    //build (incomplete/initial) forwarding table using bellman ford's to ifnd estimated least cost paths
    initBellman(My_ID);

    for(int i=0; i<Edge_List.num_edges; i++){
	int srcId = Edge_List.edges[i]->src_id;
	int dstId = Edge_List.edges[i]->dst_id;
	if(srcId == My_ID){
    	    //repeatedly send heartbeats to all neighbors
    	    send_heartbeat(dstId, unused); 
    	    //send distance vector to all neighbors
    	    send_distance_vector(dstId);
    	    //set a timer to declare link failure if no heartbeat echo in 10 seconds
    	    E_queue(link_failed, dstId, &My_ID, Lost_Con_Timeout);
	}
    }

}

uint32_t ip_from_str(char *ip)
{
    struct in_addr addr;

    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

void process_conf(char *fname, int my_id)
{
    char     buf[MAX_CONF_LINE];
    char     ip_str[MAX_CONF_LINE];
    FILE *   f        = NULL;
    uint32_t id       = 0;
    uint16_t port     = 0;
    uint32_t src      = 0;
    uint32_t dst      = 0;
    uint32_t cost     = 0;
    int node_sec_done = 0;
    int ret           = -1;
    struct node n;
    struct edge e;
    struct node *retn = NULL;
    struct edge *rete = NULL;

    Alarm(DEBUG, "Processing configuration file %s\n", fname);

    /* Open configuration file */
    f = fopen(fname, "r");
    if (f == NULL) {
        Alarm(EXIT, "overlay_node: error: failed to open conf file %s : %s\n",
              fname, strerror(errno));
    }

    /* Read list of nodes from conf file */
    while (fgets(buf, MAX_CONF_LINE, f)) {
        Alarm(DEBUG, "Read line: %s", buf);

        if (!node_sec_done) {
            // sscanf
            ret = sscanf(buf, "%u %s %hu", &id, ip_str, &port);
            Alarm(DEBUG, "    Node ID: %u, Node IP %s, Port: %u\n", id, ip_str, port);
            if (ret != 3) {
                Alarm(DEBUG, "done reading nodes\n");
                node_sec_done = 1;
                continue;
            }

            if (id == my_id) {
                Alarm(DEBUG, "Found my ID (%u). Setting IP and port\n", id);
                My_Port = port;
                My_IP = ip_from_str(ip_str);
            }

            n.id = id;
            memset(&n.addr, 0, sizeof(n.addr));
            n.addr.sin_family = AF_INET;
            n.addr.sin_addr.s_addr = htonl(ip_from_str(ip_str));
            n.addr.sin_port = htons(port);
            n.next_hop = NULL;
            retn = add_node_to_list(&Node_List, n);
            if (retn == NULL) {
                Alarm(EXIT, "Failed to add node to list\n");
            }

        } else { /* Edge section */
            ret = sscanf(buf, "%u %u %u", &src, &dst, &cost);
            Alarm(DEBUG, "    Src ID: %u, Dst ID %u, Cost: %u\n", src, dst, cost);
            if (ret != 3) {
                Alarm(DEBUG, "done reading nodes\n");
                node_sec_done = 1;
                continue;
            }

            e.src_id = src;
            e.dst_id = dst;
            e.cost = cost;
            e.src_node = get_node_from_id(&Node_List, e.src_id);
            e.dst_node = get_node_from_id(&Node_List, e.dst_id);
            if (e.src_node == NULL || e.dst_node == NULL) {
                Alarm(EXIT, "Failed to find node for edge (%u, %u)\n", src, dst);
            }
            rete = add_edge_to_list(&Edge_List, e);
            if (rete == NULL) {
                Alarm(EXIT, "Failed to add edge to list\n");
            }
        }
    }
}

int 
main(int argc, char ** argv) 
{
    char * conf_fname    = NULL;

    if (PRINT_DEBUG) {
        Alarm_set_types(DEBUG);
    }

    /* parse args */
    if (argc != 4) {
        Alarm(EXIT, "usage: overlay_node <id> <config_file> <mode: LS/DV>\n");
    }

    My_ID      = atoi(argv[1]);
    conf_fname = argv[2];

    if (!strncmp("LS", argv[3], 3)) {
        Route_Mode = MODE_LINK_STATE;
    } else if (!strncmp("DV", argv[3], 3)) {
        Route_Mode = MODE_DISTANCE_VECTOR;
    } else {
        Alarm(EXIT, "Invalid mode %s: should be LS or DV\n", argv[5]);
    }

    Alarm(DEBUG, "My ID             : %d\n", My_ID);
    Alarm(DEBUG, "Configuration file: %s\n", conf_fname);
    Alarm(DEBUG, "Mode              : %d\n\n", Route_Mode);

    process_conf(conf_fname, My_ID);
    Alarm(DEBUG, "My IP             : "IPF"\n", IP(My_IP));
    Alarm(DEBUG, "My Port           : %u\n", My_Port);

    { /* print node and edge lists from conf */
        int i;
        struct node *n;
        struct edge *e;
        for (i = 0; i < Node_List.num_nodes; i++) {
            n = Node_List.nodes[i];
            Alarm(DEBUG, "Node %u : "IPF":%u\n", n->id,
                  IP(ntohl(n->addr.sin_addr.s_addr)),
                  ntohs(n->addr.sin_port));
        }

        for (i = 0; i < Edge_List.num_edges; i++) {
            e = Edge_List.edges[i];
            Alarm(DEBUG, "Edge (%u, %u) : "IPF":%u -> "IPF":%u\n",
                  e->src_id, e->dst_id,
                  IP(ntohl(e->src_node->addr.sin_addr.s_addr)),
                  ntohs(e->src_node->addr.sin_port),
                  IP(ntohl(e->dst_node->addr.sin_addr.s_addr)),
                  ntohs(e->dst_node->addr.sin_port));
        }
    }
    

    /* Initialize event system */
    E_init();

    /* Set up TCP socket for client connection requests */
    init_client_sock(My_Port);

    /* Set up UDP sockets for sending and receiving messages from other
     * overlay nodes */
    init_overlay_data_sock(My_Port);
    init_overlay_ctrl_sock(My_Port+1);

    if (Route_Mode == MODE_LINK_STATE) {
        init_link_state();
    } else {
        init_distance_vector();
    }

    /* Enter event handling loop */
    Alarm(DEBUG, "Entering event loop!\n");
    E_handle_events();

    return 0;
}
