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

#include "packets.h"

#define PRINT_DEBUG 1

struct overlay_data {
    uint32_t           ip;
    uint32_t           id;
    uint16_t           ctrl_port;
    struct sockaddr_in ctrl_addr;
    int                ctrl_sock;
    int                ctrl_established;

    uint16_t           data_port;
    struct sockaddr_in data_addr;
    int                data_sock;
    int                data_established;

    uint32_t           dst_id;
    uint16_t           dst_port;
};

static struct overlay_data Overlay_State;
static const sp_time Data_Timeout = {1, 0};

void send_initial_data_pkt(int unused, void *state);

void handle_stdin(int fd, int code, void *data)
{
    char * retc;
    int ret;
    struct data_pkt pkt;

    struct overlay_data *state = (struct overlay_data *) data;

    retc = fgets(pkt.payload, sizeof(pkt.payload), stdin);
    if (retc == NULL) {
        Alarm(EXIT, "overlay_client: error reading from keyboard\n");
    }

    pkt.hdr.dst_id = state->dst_id;
    pkt.hdr.dst_port = state->dst_port;

    pkt.hdr.data_len = strlen(pkt.payload);

    pkt.hdr.path_len = 0;
    memset(pkt.hdr.path, 0, sizeof(pkt.hdr.path));

    Alarm(DEBUG, "sending %d bytes: %s\n", pkt.hdr.data_len, pkt.payload);
    ret = sendto(state->data_sock, &pkt,
                 sizeof(struct data_pkt)-MAX_PAYLOAD_SIZE+pkt.hdr.data_len, 0,
                 (struct sockaddr *)&state->data_addr,
                 sizeof(state->data_addr));
    if (ret < 0) {
        Alarm(EXIT, "overlay_client: error sending to overlay node\n");
    }
}

void handle_overlay_data(int sock, int unused, void *data)
{
    struct data_pkt pkt;
    char tmp_payload[MAX_PAYLOAD_SIZE+1];
    int bytes;
    socklen_t fromlen;
    struct sockaddr_in recv_addr;
    int i;

    struct overlay_data *state = (struct overlay_data *)data;

    Alarm(DEBUG, "overlay_client: received overlay data msg!\n");

    if (!state->data_established) {
        Alarm(DEBUG, "overlay_client: received data from overlay. data established\n");
        state->data_established = 1;

        /* Now that data connection is established, go ahead and attach stdin
         * to read input data */
        E_attach_fd(0, READ_FD, handle_stdin, 0, state, MEDIUM_PRIORITY);

        /* Cancel timeout */
        E_dequeue(send_initial_data_pkt, 0, state);
    }

    fromlen = sizeof(recv_addr);
    bytes = recvfrom(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&recv_addr, &fromlen);
    if (bytes < 0) {
        Alarm(EXIT, "overlay client: Error receiving from overlay node: %s\n", strerror(errno));
    }

    if (pkt.hdr.data_len == 0) {
        return;
    }

    /* Copy into buffer that ensures space for terminating null byte and print */
    memcpy(tmp_payload, pkt.payload, pkt.hdr.data_len);
    tmp_payload[pkt.hdr.data_len] = '\0';
    Alarm(PRINT, "Got data packet of %d bytes: %s\n", pkt.hdr.data_len, tmp_payload);
    Alarm(PRINT, "packet path len %d:", pkt.hdr.path_len);
    for (i = 0; i < pkt.hdr.path_len; i++) {
        Alarm(PRINT, " %d", pkt.hdr.path[i]);
    }
    Alarm(PRINT, "\n\n");
}

void send_initial_data_pkt(int unused, void *data)
{
    int ret = 0;
    struct data_pkt_hdr pkt;
    struct overlay_data *state = (struct overlay_data *)data;

    if (state->data_established) {
        Alarm(DEBUG, "overlay_client: data already established, ending initial data pkt retransmission\n");
        return;
    }

    Alarm(DEBUG, "Sending initial data packet\n");
    pkt.dst_id = state->id;
    pkt.dst_port = state->data_port;
    pkt.data_len = 0;
    ret = sendto(state->data_sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&state->data_addr, sizeof(state->data_addr));
    if (ret < 0) {
        Alarm(EXIT, "overlay client: Error sending initial data pkt: %s\n", strerror(errno));
    }

    /* Enqueue resending data packet to handle lost packet */
    E_queue(send_initial_data_pkt, 0, state, Data_Timeout);

}

void init_overlay_data_sock(struct overlay_data *state)
{
    int ret = 0;

    if (!state->ctrl_established) {
        Alarm(EXIT, "overlay_client: Error: data setup called before control established\n");
    }

    if ((state->data_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        Alarm(EXIT, "overlay_client: data socket error: %s\n", strerror(errno));
    }

    /* Assumes ctrl addr is already set up correctly... */
    state->data_addr = state->ctrl_addr;
    state->data_addr.sin_port = htons(state->data_port);

    /* Send initial packet to register data socket and allow overlay node to
     * setup return address correctly */
    send_initial_data_pkt(0, state);

    /* Register socket with event handling system */
    ret = E_attach_fd(state->data_sock, READ_FD, handle_overlay_data, 0, state, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register overlay data sock in event handling system\n");
    }

}

void handle_overlay_ctrl(int ctrl_sock, int unused, void *data)
{
    int    ret               = 0;
    int    bytes_read        = 0;
    char * err_str           = "server closed connection";
    struct conn_ack_pkt resp;
    /*struct overlay_data *state = (struct overlay_data *)data;*/

    Alarm(DEBUG, "overlay_client: received overlay control msg!\n");

    bytes_read = 0;
    while (bytes_read < sizeof(resp) &&
           (ret = recv(ctrl_sock, ((char *)&resp)+bytes_read, sizeof(resp)-bytes_read, 0)) > 0) {
        bytes_read += ret;
    }
    if (ret <= 0) {
        if (ret < 0) err_str = strerror(errno);
        Alarm(EXIT, "Recv returned %d; Overlay connection terminated: %s\n", ret, err_str);
    }
}

uint32_t ip_from_str(char *ip)
{
    struct in_addr addr;

    inet_pton(AF_INET, ip, &addr);
    return ntohl(addr.s_addr);
}

int 
main(int argc, char ** argv) 
{
    char * overlay_IP        = NULL;
    int    ret               = 0;
    int    bytes_sent        = 0;
    int    bytes_read        = 0;

    struct hostent h_ent, *p_h_ent;
    struct sockaddr_in overlay_addr;
    struct conn_req_pkt req;
    struct conn_ack_pkt resp;

    if (PRINT_DEBUG) {
        Alarm_set_types(DEBUG);
    }

    /* parse args */
    if (argc != 6) {
        Alarm(EXIT, "usage: ./overlay_client <overlay_node_IP> <overlay_node_port> <client_data_port> <destination_overlay_node_ID> <destination_client_port>\n");
    }

    overlay_IP              = argv[1];
    Overlay_State.ctrl_port = atoi(argv[2]);
    Overlay_State.data_port = atoi(argv[3]);
    Overlay_State.dst_id    = atoi(argv[4]);
    Overlay_State.dst_port  = atoi(argv[5]);

    Overlay_State.ctrl_established = 0;
    Overlay_State.data_established = 0;

    Alarm(DEBUG, "Overlay IP         : %s\n", overlay_IP);
    Alarm(DEBUG, "Overlay Ctrl. Port : %d\n", Overlay_State.ctrl_port);
    Alarm(DEBUG, "Overlay Data Port  : %d\n", Overlay_State.data_port);
    Alarm(DEBUG, "Overlay Dst ID     : %u\n", Overlay_State.dst_id);
    Alarm(DEBUG, "Overlay Dst Port   : %d\n", Overlay_State.dst_port);

    /* Initialize event system */
    E_init();

    /* Init socket */
    Overlay_State.ctrl_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (Overlay_State.ctrl_sock < 0) {
        Alarm(EXIT, "overlay_client: Failed to create control socket: %s\n", strerror(errno));
    }

    /* Set up server address */
    memset(&overlay_addr, 0, sizeof(struct sockaddr_in));
    Overlay_State.ctrl_addr.sin_family = AF_INET;
    p_h_ent = gethostbyname(overlay_IP);
    if (p_h_ent == NULL) {
        Alarm(EXIT, "Invalid host name: %s\n", strerror(errno));
    }
    memcpy(&h_ent, p_h_ent, sizeof(h_ent));
    memcpy(&Overlay_State.ctrl_addr.sin_addr, h_ent.h_addr_list[0], sizeof(Overlay_State.ctrl_addr.sin_addr));
    Overlay_State.ctrl_addr.sin_port = htons(Overlay_State.ctrl_port);

    Overlay_State.ip = ntohl(Overlay_State.ctrl_addr.sin_addr.s_addr);
    Alarm(DEBUG, "Initialized Overlay IP: " IPF "\n", IP(Overlay_State.ip));

    /* Connect to server */
    ret = connect(Overlay_State.ctrl_sock, (struct sockaddr *)&Overlay_State.ctrl_addr, sizeof(struct sockaddr_in));
    if (ret < 0) {
        Alarm(EXIT, "Failed to connect to overlay: %s\n", strerror(errno));
    }
    Alarm(DEBUG, "Successfully connected!\n");

    /* Send request */
    bytes_sent = 0;
    req.port = Overlay_State.data_port;
    while (bytes_sent < sizeof(req)) {
        ret = send(Overlay_State.ctrl_sock, ((char*)&req)+bytes_sent, sizeof(req)-bytes_sent, 0);
        if (ret <= 0) {
            Alarm(EXIT, "Sending initial request to overlay node failed: %s\n", strerror(errno));
        }
        bytes_sent += ret;
        Alarm(DEBUG, "Sent %d / %d bytes\n", ret, sizeof(req));
    }
    
    /* Read response. Blocking recv, since we shouldn't send any data until
     * connection is established */
    bytes_read = 0;
    while (bytes_read < sizeof(resp) &&
           (ret = recv(Overlay_State.ctrl_sock, ((char *)&resp)+bytes_read,
                       sizeof(resp)-bytes_read, 0)) > 0)
    {
        bytes_read += ret;
    }
    if (ret <= 0) {
        Alarm(EXIT, "Recv returned %d; Failed to establish overlay connection: %s\n", ret, strerror(errno));
    }

    /* Check whether overlay node accepted or rejected our request */
    if (resp.id == 0) { /* rejected */
        Alarm(EXIT, "Recvd response %d from overlay node. Connection rejected.\n", resp.id);
    }
    Overlay_State.id = resp.id;
    Alarm(DEBUG, "Connection accepts. Set overlay ID to %u\n", Overlay_State.id);

    /* Register control socket */
    ret = E_attach_fd(Overlay_State.ctrl_sock, READ_FD, handle_overlay_ctrl, 0, &Overlay_State, MEDIUM_PRIORITY);
    if (ret < 0) {
        Alarm(EXIT, "Failed to register control socket in event system\n");
    }

    Overlay_State.ctrl_established = 1;

    /* Init socket for sending and receiving data from overlay */
    init_overlay_data_sock(&Overlay_State);

    /* Enter event handling loop */
    Alarm(DEBUG, "Entering event loop!\n");
    E_handle_events();

    return 0;
}
