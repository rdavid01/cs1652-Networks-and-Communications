#define MAX_PAYLOAD_SIZE 1300
#define MAX_CTRL_SIZE 1300
#define MAX_PATH 8
#define MAX_NODES 100

struct data_pkt_hdr {
    uint32_t dst_id; /* ID of destination overlay node */
    uint32_t src_id; /* ID of source overlay node; only filled in by overlay node (not client) */
    uint16_t dst_port; /* port where dst client is connected to dst overlay node */
    uint16_t src_port; /* only filled in by overlay node */
    uint32_t data_len;
    uint32_t path_len; /* length of path */
    uint8_t  path[8]; /* sequence of overlay nodes this packet passed through */
} __attribute__((packed));

struct data_pkt {
    struct data_pkt_hdr hdr;
    char                payload[MAX_PAYLOAD_SIZE];
} __attribute__((packed));

/* The type field in the struct ctrl_hdr should be one of these values to
 * identify the type of the packet */
#define CTRL_HEARTBEAT      1
#define CTRL_HEARTBEAT_ECHO 2
#define CTRL_LSA            3
#define CTRL_DV             4

struct ctrl_hdr {
    uint32_t type;
    uint32_t src_id;
    uint32_t dst_id;
} __attribute__((packed));

struct heartbeat_pkt {
    struct ctrl_hdr hdr;
    /* you may add additional fields here (if needed) */
} __attribute__((packed));

struct heartbeat_echo_pkt {
    struct ctrl_hdr hdr;
    /* you may add additional fields here (if needed) */
} __attribute__((packed));

/* Link state advertisement */
struct lsa_pkt {
    struct ctrl_hdr hdr;
    /* you should define the fields needed here */
    int             updateNum;
    int             origin;
    int            updateRow[MAX_NODES];
} __attribute__((packed));

/* Distance vector update */
struct dv_pkt {
    struct ctrl_hdr hdr;
    /* you should define the fields needed here */
    int            DVRow[MAX_NODES];
    int            fwdRow[MAX_NODES];
} __attribute__((packed));


/* These packets are only used for establishing a client connection to an
 * overlay node. You should not need to modify these */
struct conn_req_pkt {
    uint16_t port;
} __attribute__((packed));

struct conn_ack_pkt {
    uint32_t id;
} __attribute__((packed));

