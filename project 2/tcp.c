/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"
#include "timer.h"


extern int petnet_errno;

struct tcp_state {
    struct tcp_con_map * con_map;
};

static void timeout_callback(struct pet_timeout * timeout, 
		             void               * arg);


static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}


static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt, 
               uint32_t        option_len)
{
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}

static uint16_t
__calculate_chksum(struct tcp_connection * con,
                   struct ipv4_addr      * remote_addr,
                   struct packet         * pkt)
{
    struct ipv4_pseudo_hdr hdr;
    uint16_t checksum = 0;

    memset(&hdr, 0, sizeof(struct ipv4_pseudo_hdr));

    ipv4_addr_to_octets(con->ipv4_tuple.local_ip,  hdr.src_ip);
    ipv4_addr_to_octets(remote_addr,               hdr.dst_ip);

    hdr.proto  = IPV4_PROTO_TCP;
    hdr.length = htons(pkt->layer_4_hdr_len + pkt->payload_len);

    checksum = calculate_checksum_begin(&hdr, sizeof(struct ipv4_pseudo_hdr) / 2);
    checksum = calculate_checksum_continue(checksum, pkt->layer_4_hdr, pkt->layer_4_hdr_len / 2);
    checksum = calculate_checksum_continue(checksum, pkt->payload,     pkt->payload_len     / 2);

    /* 
     * If there is an odd number of data bytes we have to include a 0-byte after the the last byte 
     */
    if ((pkt->payload_len % 2) != 0) {
        uint16_t tmp = *(uint8_t *)(pkt->payload + pkt->payload_len - 1);

        checksum = calculate_checksum_finalize(checksum, &tmp, 1);
    } else {
        checksum = calculate_checksum_finalize(checksum, NULL, 0);
    }

    return checksum;
}


//===================================================================================================
/* ****************************************************************************************
 * send_response() creates a new packet that will be sent to the other host.
 * con is the connection to be used.
 * synSet, ackSet, and finSet are used to set the packet's flags.
 * sendingPayload is a boolean used to determine if a payload should be added to the packet.
 * ****************************************************************************************/
int send_response(struct tcp_connection* con,
		  int                    synSet,
		  int			 ackSet,
		  int			 finSet,
		  int                    sendingPayload
	         )
{
    struct ipv4_addr * remote_ip   = NULL;
    uint16_t           remote_port = 0;
    uint16_t           local_port  = 0;

    remote_ip   = con->ipv4_tuple.remote_ip;
    local_port  = con->ipv4_tuple.local_port;
    remote_port = con->ipv4_tuple.remote_port;

    //returns amount of data waiting in the sockets outbound buffer
    uint32_t sendCap = pet_socket_send_capacity(con->sock);
    //error if buffer is empty and want to send payload (checking before create packet)
    if(sendCap == 0 && sendingPayload && con->resending != 1){
	log_error("buffer is empty, no payload to send\n");
        return -1;
    }

    /*create packet*/
	struct packet * responsePacket = NULL;
	responsePacket = create_empty_packet();

	//create payload if flagged
	if(sendingPayload == 1){
    	    //--TIMEOUT--
	    if(con->resending == 1){
		//use data saved in con's buffer, already read from socket
	        responsePacket->payload_len = con->payload_len;
	     	responsePacket->payload     = pet_malloc(con->payload_len);
		memcpy(responsePacket->payload, con->buf, con->payload_len);
	    }
	    else{
	        responsePacket->payload_len = sendCap;
	        responsePacket->payload = pet_malloc(sendCap);
	        pet_socket_sending_data(con->sock, 
			    	        responsePacket->payload, 
				        responsePacket->payload_len
				       );
	    }
	}

	//create tcp header with SYN and ACK flags set
	struct tcp_raw_hdr * responseHeader = NULL;
	responseHeader = __make_tcp_hdr(responsePacket, 0);//header with no options
	responseHeader->src_port   = htons(local_port); 
	responseHeader->dst_port   = htons(remote_port);
	responseHeader->seq_num    = htonl(con->conSN);
	responseHeader->ack_num    = htonl(con->conAN);  
	//NOTE: not htons or htonl because length and flags are a single byte (uint8_t)
	responseHeader->header_len = 5; //number of bytes in used in header (5*4 = 20) 
	//flags
	if(synSet){
	    responseHeader->flags.SYN = 1;
	}
	if(ackSet){
	    responseHeader->flags.ACK  = 1;
	}
	if(finSet){
	    responseHeader->flags.FIN  = 1;
	}
        //checksum 
    	responseHeader->checksum = __calculate_chksum(con, remote_ip, responsePacket);
	//receive window
	int rcvCap = pet_socket_recv_capacity(con->sock);
	int winSize = 0;
	if(rcvCap <= 65535){
	    //available space in socket's return buffer is <= the advertised window size
	    winSize = rcvCap;
	}
	else{
	   //advertised window is greter than available space in socket's return buffer
	   winSize = 65535;
	}
	responseHeader->recv_win = htons(winSize);


    //print packet if in debugging mode
    if(petnet_state->debug_enable){
    	pet_printf("test responseHeader\n");
    	print_tcp_header(responseHeader);
    }

    //--TIMEOUT--
    //save properties of last sent packet in case need to retransmit
        con->synSet = synSet;
        con->ackSet = ackSet;
        con->finSet = finSet;
        con->sendingPayload = sendingPayload;
        memset(con->buf, 0, sizeof(con->buf));
        memcpy(con->buf, responsePacket->payload, responsePacket->payload_len);
        con->payload_len = responsePacket->payload_len;

    con->resending = 0;//reset to indicate done retransmitting (if were retransmitting)

    //send the packet, free packet if error
    int retTx = ipv4_pkt_tx(responsePacket, remote_ip);
    if(retTx == -1){
	free_packet(responsePacket);
	log_error("Error sending packet\n");
	return -1;
    }	

    //--TIMEOUT--
    //retransmit if necessary
    	//not expecting a response 
    if((con->con_state != CLOSED)      && 
       (con->con_state != TIME_WAIT)   &&
       (con->con_state != CLOSE_WAIT)  &&
       !(con->con_state == ESTABLISHED && responsePacket->payload_len == 0)
      )
    {
	    con->timedOut = 0;
	    con->timeoutStarted = 1;
	    unlock_tcp_con(con);
	    con->timeout = pet_add_timeout(5,
			    		   timeout_callback,
			   		   con 
			   		  );
	    lock_tcp_con(con);
    }

    return 0;
}

//===================================================================================================
/* *******************************************************************************
 * timeout_callback() is called whenever a timeout expires.
 * It calls send_response using data to recreate the last packet sent by this host.
 * timeout is the timeout that expired.
 * arg is the connection over which we want to resend.
 * *******************************************************************************/
//--TIMEOUT--
static void timeout_callback(struct pet_timeout * timeout,
	       	               void               * arg){
	struct tcp_connection * con = arg;

	lock_tcp_con(con);
	con->timedOut = 1; //timeout has expired
	con->resending = 1;//retransmit packet using properties stored in con

	//retransmit
	send_response(con,
		      con->synSet,
		      con->ackSet,
		      con->finSet,
		      con->sendingPayload
		     );
	
	con->timeoutStarted = 0; //timeout and retransmisttion finished
	unlock_tcp_con(con);

	return;
}

//===================================================================================================
/* *********************************************************************************************
 * tcp_listen() enables interaction with the socket layer.
 * Whenever pet_listen() is called, this implementation creates a new connection to listen for 
 * incoming connection requests.
 * No remote port or ip address is known yet, so it uses temporary values to create a connection.
 * *********************************************************************************************/
int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{
    struct tcp_state      * tcp_state  = petnet_state->tcp_state;
    struct tcp_connection * con        = NULL;

    struct ipv4_addr      * remote_addr = NULL;
    uint16_t                remote_port = 0;

    //0.0.0.0 designates invalid, unknown, or unapplicable target 
    	//indicates client isn't connected to TCP/IP network
    remote_addr = ipv4_addr_from_str("0.0.0.0");
    int addSock = 0;

    //create listening connection
    con = create_ipv4_tcp_con(tcp_state->con_map,
		              local_addr,
			      remote_addr,
			      local_port,
			      remote_port
			     );
    if(con == NULL){
	log_error("Could not find tcp connection\n");
	goto out;
    }

    //associate the provided socket with this connection (can be referenced in the future)
    addSock = add_sock_to_tcp_con(tcp_state->con_map,
		                  con,
				  sock
				 );
    if(addSock == -1){
        log_error("Error adding sock to connection\n");
	goto out;
    }

    con->con_state = LISTEN; //listening
    put_and_unlock_tcp_con(con);

    return 0;

out:
    if (con) put_and_unlock_tcp_con(con);
    return -1;
}

//===================================================================================================
/* *********************************************************************************
 * tcp_send_FIN() sends a packet with FIN-ACK flags to initiate connection teardown.
 * *********************************************************************************/
int tcp_send_FIN(struct tcp_connection* con)
{
	//FIN_WAIT_1 ------ FIN-ACK ------> CLOSE_WAIT
	uint32_t seqNum = 0;
	uint32_t ackNum = 0;
	ackNum      = con->conAN;
	seqNum      = con->conSN;
	//set connection sequence numbers for server and client
	con->conSN = seqNum;
	con->conAN = ackNum;

	if(con->con_state == ESTABLISHED){
		con->con_state = FIN_WAIT1;
	}

	//send a FIN-ACK packet
	int synSet          = 0;
	int ackSet          = 1;
	int finSet          = 1;
	int sendingPayload  = 0;
	int sendRet = send_response(con,
				    synSet,
				    ackSet,
				    finSet,
			  	    sendingPayload		    
			  	    );

	if(sendRet == -1){
	    return -1;
	}
	
	return 0;
}

//===================================================================================================
/* ********************************************************************************
 * tcp_send_SYN() sends a packet with SYN flagged in order to initiate a connection.
 * ********************************************************************************/
int tcp_send_SYN(struct tcp_connection* con)
{
	// SYN_SENT ----- SYN ------> SYN_RCV

	//set connection sequence numbers for server and client
	con->conSN = 0;
	con->conAN = 0;

	//send a SYN packet
	int synSet 	   = 1;
	int ackSet 	   = 0;
	int finSet         = 0;
	int sendingPayload = 0;
	int sendRet = send_response(con,
				    synSet,
				    ackSet,
				    finSet,
				    sendingPayload
				   );
	if(sendRet == -1){
	    return -1;
	}
	
	con->con_state = SYN_SENT;//syn packet sent
	return 0;
}

//===================================================================================================
/* **********************************************************************************************
 * tcp_connect_ipv4() uses information provided by the socket in order to create a new connection.
 * It also sends a SYN packet to the other host in order to start the handshake process.
 * **********************************************************************************************/
int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * local_addr, 
                 uint16_t           local_port,
                 struct ipv4_addr * remote_addr,
                 uint16_t           remote_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con       = NULL;

    //create new connection
    con = create_ipv4_tcp_con(tcp_state->con_map,
	       	              local_addr,
			      remote_addr,
			      local_port,
			      remote_port 
			     );
    if(con == NULL){
	log_error("Could not find tcp connection\n");
	goto out;
    }

    //assoicate sock with connection (so can be referenced in future)
    int ret = add_sock_to_tcp_con(tcp_state->con_map,
              		          con,
                        	  sock
                       		 );
    if(ret == -1){
	log_error("Could not add sock to tcp connection\n");
	goto out;
    }

    //send SYN packet to start handshake
    int retSend = tcp_send_SYN(con);
    if(retSend == -1){
	log_error("Error sending packet\n");
	goto out;
    }

    put_and_unlock_tcp_con(con);
    return 0;

out:
    if (con) put_and_unlock_tcp_con(con);
    return -1;
}

//===================================================================================================
/* ******************************************************************************
 * tcp_send() and __send_data_pkt() respond to socket layer request to send data.
 * ******************************************************************************/
int __send_data_pkt(struct tcp_connection* con){
    
    uint32_t seqNum  = 0;
    uint32_t ackNum  = 0;
    seqNum     = con->conSN;
    ackNum     = con->conAN;
    //update connection sequence numbers
    con->conSN = seqNum;
    con->conAN = ackNum;

    //send a ACK data packet
    int synSet 	       = 0;
    int ackSet 	       = 1;
    int finSet         = 0;
    int sendingPayload = 1; //sending payload
    int sendRet = send_response(con,
				synSet,
				ackSet,
				finSet,
				sendingPayload
			       );
    if(sendRet == -1){
        return -1;
    }
   	
    return 0;
}

int
tcp_send(struct socket * sock)
{
	struct tcp_state * tcp_state = petnet_state->tcp_state;
	struct tcp_connection * con = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);
 
	if (con->con_state != ESTABLISHED) {
		log_error("TCP connection is not established\n");
		goto out;
	}

	int retSend = __send_data_pkt(con);
	if(retSend == -1){
	    log_error("failed to send packet\n");
	    goto out;
	}

	put_and_unlock_tcp_con(con);
	return 0;

out:
	if (con) put_and_unlock_tcp_con(con);
	return -1;
}

//===================================================================================================
/* ************************************************************************************
 * tcp_close() begins the connection teardown process after the socket has been closed.
 * It sends a packet with FIN flagged in order to start the termination sequence.
 * ***********************************************************************************/
/* Petnet assumes SO_LINGER semantics, so if we'ere here there is no pending write data */
int
tcp_close(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con       = NULL;
   

    con = get_and_lock_tcp_con_from_sock(tcp_state->con_map,
		    			 sock
					);
    if (con == NULL) {
	log_error("TCP connection is not established\n");
	goto out;
    }
  
    //send FIN to initiate connection termination
    int retSend = tcp_send_FIN(con);	 
    if(retSend == -1){
        log_error("Error sending packet\n");
	goto out;
    }

    put_and_unlock_tcp_con(con);
    return 0;
out:
    if (con) put_and_unlock_tcp_con(con);
    return -1;
}

//===================================================================================================
/* *****************************************************************************************
 * Various functions were created to respond to packets with SYN, SYN-ACK, ACK, or FIN flags.
 * These functions handle connection state changes, adjust sequence and ack numbers, and call 
 * send_response() in order to respond to the packet that was just received.
 * *****************************************************************************************/
int tcp_respond_to_SYN(struct tcp_connection * con,
		       uint32_t                seqNum_rcv,
		       uint32_t	               ackNum_rcv
		      )
{

    //update state, received syn
    con->con_state = SYN_RCVD;

    //update connection sequence numbers
    con->conSN = ackNum_rcv;
    con->conAN = seqNum_rcv+1;

    //send a SYN-ACK data packet
    int synSet 	       = 1;
    int ackSet 	       = 1;
    int finSet         = 0;
    int sendingPayload = 0;
    int sendRet = send_response(con,
				synSet,
				ackSet,
				finSet,
				sendingPayload
			       );
    if(sendRet == -1){
        goto out;
    }

    return 0;

out:
    return -1;
}


//respond to a SYNACK by sending an ACK
int tcp_respond_to_SYNACK(struct tcp_connection * con,
		 	  uint32_t           seqNum_rcv,
		 	  uint32_t           ackNum_rcv
			 )
{

    //update sequence number and ack
    con->conSN = ackNum_rcv;
    con->conAN = seqNum_rcv+1;

    //send a ACK data packet
    int synSet 	       = 0;
    int ackSet 	       = 1;
    int finSet         = 0;
    int sendingPayload = 0;
    int sendRet = send_response(con,
				synSet,
				ackSet,
				finSet,
				sendingPayload
			       );
    if(sendRet == -1){
        goto out;
    }

    //update state to be established
    con->con_state = ESTABLISHED;
    //notify socket that connection was successful
    pet_socket_connected(con->sock);

    return 0;

out:
    return -1;
}


int tcp_respond_to_ACK(struct tcp_state      * tcp_state,
		       struct tcp_connection * con,
		       uint32_t                seqNum_rcv,
		       uint32_t	    	       ackNum_rcv,
		       struct packet         * rcv_pkt
		      )
{
    void                    * payload = NULL;
    uint32_t                  pay_len = 0;

//handle state change
    if(con->con_state == SYN_RCVD){
	// snd: ESTABLISHED <------ SYN-ACK ------ SYN_RCVD
	// rcv: ESTABLISHED ------ ACK ------> ESTABLISHED
    	con->con_state = ESTABLISHED;
    }
    else if(con->con_state == FIN_WAIT1){
	// snd: FIN_WAIT1 ------ FIN-ACK ------> CLOSE_WAIT
	// rcv: FIN_WAIT2 <------ ACK ------ CLOSE_WAIT
	con->con_state = FIN_WAIT2;
    }
    else if(con->con_state == LAST_ACK){
	// snd: TIME_WAIT <------ FIN-ACK ------ LAST_ACK
	// rcv: TIME_WAIT ------ ACK ------> CLOSED
	con->con_state = CLOSED;
    }
    else if(con->con_state == ESTABLISHED){
        //otherwise, if the connection is ESTABLISHED and rcv an ACK, it stays ESTABLISHED
        // ESTABLISHED ------ ACK ------> ESTABLISHED
	
	//get payload from incoming packet
        payload = __get_payload(rcv_pkt);
        pay_len = rcv_pkt->payload_len;

        if(pay_len > 0){
	    // rcv: ESTABLISHED ------ ACK <DATA> ------> ESTABLISHED
	    // snd: reply with an ACK

    	    con->conSN = ackNum_rcv;
    	    con->conAN = seqNum_rcv+pay_len; //increment by payload length

	    //ensure enough space in socket ring buffer using pet_socket_recv_capacity()
	    if(pet_socket_recv_capacity(con->sock) == 0){
		    goto out;
 	    }
	    int rcvData = pet_socket_received_data(con->sock, 
					           payload,
					           pay_len
	  				          );
            if(rcvData == -1){
    	        log_error("Failed to receive datagram\n");
	        goto out;
            }
 
    	    //send a ACK data packet
    	    int synSet 	       = 0;
    	    int ackSet 	       = 1;
    	    int finSet         = 0;
    	    int sendingPayload = 0;
    	    int sendRet = send_response(con,
	   			        synSet,
					ackSet,
					finSet,
					sendingPayload
			       	       );
    	    if(sendRet == -1){
        	goto out;
    	    }
        }
        else{ //no payload in incoming packet
    	    con->conSN = ackNum_rcv;
    	    con->conAN = seqNum_rcv;
	    //close socket, non-persistent connection
	    pet_socket_closed(con->sock);
        }
    }

    return 0;

out:
    return -1;
}

//----------------------------------------------------------------------
/* ********************************************************************
 * tcp_respond_to_FIN() is the first step in responding to a FIN.
 * It sends an ACK packet and changes state to CLOSE-WAIT.
 * tcp_respond_to_FIN_Part2() is the second step in responding to a FIN.
 * It sends a FIN-ACK packet and changes state to TIME-WAIT.
 * ********************************************************************/

int tcp_respond_to_FIN_Part2(struct tcp_connection * con)
{

    con->con_state = LAST_ACK; //state change, expecting last ack

    // ackNum and seqNum should be same as in first part of FIN response
    //dont set to be what we rcv, this will just reset it to before the update in respond_to_FIN

    //send a FIN-ACK data packet
    int synSet 	       = 0;
    int ackSet 	       = 1;
    int finSet         = 1;
    int sendingPayload = 0;
    int sendRet = send_response(con,
				synSet,
				ackSet,
				finSet,
				sendingPayload
			       );
    if(sendRet == -1){
       	goto out;
    }

    return 0;

out:
    return -1;
}

//respond to a FIN 
int tcp_respond_to_FIN(struct tcp_state      * tcp_state,
		       struct tcp_connection * con,
		       uint32_t                seqNum_rcv,
		       uint32_t                ackNum_rcv
		      )
{

    //handle state change
    if(con->con_state == ESTABLISHED){
	// rcv: FIN_WAIT1 ------ FIN-ACK ------> CLOSE_WAIT
	// snd: FIN_WAIT2 <------ ACK ------ CLOSE_WAIT
	con->con_state = CLOSE_WAIT;
    }
    else if(con->con_state == FIN_WAIT2){
	// rcv: FIN_WAIT2 <------ ACK ------ CLOSE_WAIT
	// rcv: TIME_WAIT <------ FIN-ACK ------ LAST_ACK
	con->con_state = TIME_WAIT;
    }
    else if(con->con_state == FIN_WAIT1){
	// snd: FIN_WAIT1 ------ FIN-ACK ------> CLOSE_WAIT
	// rcv: FIN_WAIT2 <------ ACK ------ LAST_ACK 
	con->con_state = TIME_WAIT;
    }

    //update sequence number
    con->conSN = ackNum_rcv;
    con->conAN = seqNum_rcv+1;

    //send a ACK data packet
    int synSet 	       = 0;
    int ackSet 	       = 1;
    int finSet         = 0;
    int sendingPayload = 0;
    int sendRet = send_response(con,
				synSet,
				ackSet,
				finSet,
				sendingPayload
			       );
    if(sendRet == -1){
       	goto out;
    }

    //tcp state to CLOSED after send the final ack
    if(con->con_state == TIME_WAIT){
	con->con_state = CLOSED;
    }


    return 0;

out:
    return -1;
}

//===================================================================================================
/* ************************************************************************************************
 * tcp_pkt_rx() has several important roles, it is called upon receiving a packet.
 * It stores information from the packet's header that is used in determining how to respond.
 * It also creates or gets a connection.
 * 	It may need to finish setting up a complete connection if a listening server received a SYN.
 * 	Or it may just need to retreive a connection in any other case.
 * It also calls the various tcp_respond_to_...() functions in order to handle state changes and 
 * sending responses.
 * ************************************************************************************************/

int 
tcp_pkt_rx(struct packet * pkt)
{
    if (pkt->layer_3_type != IPV4_PKT) {
    	return -1;
    }

    // Handle IPV4 Packet
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct ipv4_raw_hdr   * ipv4_hdr  = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
    struct tcp_raw_hdr    * tcp_hdr   = NULL;
    
    struct tcp_connection * tempCon   = NULL;
    struct tcp_connection * con       = NULL;
    struct socket         * conSock   = NULL;

    struct ipv4_addr * remote_ip   = NULL;
    struct ipv4_addr * local_ip    = NULL;
    uint16_t           remote_port = 0;
    uint16_t           local_port  = 0;
    uint32_t           seqNum_rcv  = 0;
    uint32_t           ackNum_rcv  = 0;
    
    //get header from packet
    tcp_hdr = __get_tcp_hdr(pkt);

    //print out header (if debug mode enabled)
    if(petnet_state->debug_enable){
	pet_printf("Received TCP Datagram\n");
	print_tcp_header(tcp_hdr);
    }

    //get src and dst ip addresses from ipv4 header
    remote_ip   = ipv4_addr_from_octets(ipv4_hdr->src_ip);
    local_ip    = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
    //get src and dst port from tcp header
    remote_port = ntohs(tcp_hdr->src_port);
    local_port  = ntohs(tcp_hdr->dst_port);
    //get sequence and acknowledgement numbers from tcp header
    seqNum_rcv  = ntohl(tcp_hdr->seq_num);
    ackNum_rcv  = ntohl(tcp_hdr->ack_num);
    //booleans for which flags are set on incoming packet 
    int finFlagged = tcp_hdr->flags.FIN;
    int synFlagged = tcp_hdr->flags.SYN;
    int ackFlagged = tcp_hdr->flags.ACK;


//open connection
    if(synFlagged && !ackFlagged && !finFlagged){
	//open temporary connection used for listening server
    	struct ipv4_addr * temp_remote_ip = ipv4_addr_from_str("0.0.0.0"); 
    	uint16_t temp_remote_port = 0;
    	tempCon = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map,
		    			     local_ip,
					     temp_remote_ip,
					     local_port,
					     temp_remote_port
		    			    );
    	if(tempCon == NULL){
	    log_error("could not get TCP connection\n");
	    goto out;
        }

	//create new connection after receving SYN
    	con = create_ipv4_tcp_con(tcp_state->con_map,
		  	        local_ip,
				remote_ip,
				local_port,
				remote_port
         		       );	
    	if (con == NULL) {
	    log_error("TCP connection is not established\n");
	    goto out;
    	}

	//notify socket layer that connection accepted
        conSock = pet_socket_accepted(tempCon->sock, remote_ip, remote_port);

	//NOTE: if remove the tempCon, then server can't accept another request, if simply put and unlock, then can issue a subsequent request
	put_and_unlock_tcp_con(tempCon);

	//add the socket to the new connection
        add_sock_to_tcp_con(tcp_state->con_map,
                            con,
                            conSock
                           );
    }
    else{
    	con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map,
		  	        	     local_ip,
		       			     remote_ip,
					     local_port,
					     remote_port
         		       		    );	
    	if (con == NULL) {
	    log_error("could not get TCP connection\n");
	    goto out;
    	}
    }


//discard if the sequence number does not match what we expect 
    if((seqNum_rcv != con->conAN) && (con->con_state != CLOSED) && (con->con_state != SYN_SENT)){
	    goto out;
    }


    //--TIMEOUT--
    //when uncommented, the conditional below will force timeouts to occur when running listen_server
    	//this is to be used for testing purposes only, it is not part of the final implementation
//    if(con->payload_len > 0 && con->counter < 2){
//	con->counter++;
//        if (con) put_and_unlock_tcp_con(con);
//        return 0;
//    }

    //--TIMEOUT--
    //cancel the timeout if it has been started and hasn't expired yet
    if(con->timeoutStarted == 1){
        if(con->timedOut == 0){
   	    pet_cancel_timeout(con->timeout);
        }
	con->timedOut = 0;
	con->timeoutStarted = 0;
    } 


//check flags
    if(synFlagged && !ackFlagged && !finFlagged){
	//send SYN-ACK in response to a SYN (second part of handshake)
        int retSend = tcp_respond_to_SYN(con,
					 seqNum_rcv,
					 ackNum_rcv
		       			);	 
	if(retSend == -1){
		goto out;
	}

    }
    else if(synFlagged && ackFlagged && !finFlagged){
	//send ACK in response to SYN-ACK
        int retSend = tcp_respond_to_SYNACK(con,
					    seqNum_rcv,
					    ackNum_rcv
		       			   );	 
	if(retSend == -1){
		goto out;
	}

    }
    else if(!synFlagged && ackFlagged && !finFlagged){
	//a packet with ACK flagged is received
	int retSend = tcp_respond_to_ACK(tcp_state,
					 con,
					 seqNum_rcv,
					 ackNum_rcv,
			   		 pkt
		          		);	 
	if(retSend == -1){
		goto out;
	}
    }
    else if(!synFlagged && finFlagged){
	//a packet with FIN (or FIN and ACK) is received
	int retSend = tcp_respond_to_FIN(tcp_state,
			                 con,
		           		 seqNum_rcv,
			   		 ackNum_rcv
		          		);	 
	if(retSend == -1){
	 	   goto out;
	}

        //if just sent an ack during CLOSE_WAIT stage, follow up by sending a FIN
        if(con->con_state == CLOSE_WAIT){
	    // snd: FIN_WAIT2 <------ ACK ------ CLOSE_WAIT
            // snd: TIME_WAIT <------ FIN-ACK ------ LAST_ACK
    	    int retSend2 = tcp_respond_to_FIN_Part2(con);	 
	    if(retSend2 == -1){
	        log_error("error sending packet\n");
	        goto out;
	    }

        }
    }



    //unlock and release connection
    if(con->con_state == CLOSED){
	    if (con) remove_tcp_con(tcp_state->con_map,
			            con);
    }
    else{
	    if (con) put_and_unlock_tcp_con(con);
    }

    return 0 ;

out:
    if (con) put_and_unlock_tcp_con(con);
    return -1;
}

//===================================================================================================

int 
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));

    state->con_map  = create_tcp_con_map();

    petnet_state->tcp_state = state;
    
    return 0;
}