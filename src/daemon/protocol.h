#ifndef PROTO_H_
#define PROTO_H_ 1

#include <glib.h>
#include <gio/gio.h>
#include <stdint.h>

#include "config.h"

#define MAGIC_VAL		0x5a81

#define PROTO_VER		0

#define UDP_PORT		28960

#define PKT_TYPE_REQUEST	0
#define PKT_TYPE_REPLY		1


#pragma pack(push, 1)

/*** Main packet structure ***/
typedef struct StructPkt {
	uint16_t magic;
	uint16_t version;
	uint32_t pkt_size;
	uint8_t *serialized_payload;
} StructPkt;

typedef struct StructPayloadHdr {
	uint8_t type;
	uint8_t seq;
	uint8_t cmd_type;
} StructPayloadHdr;

/*** Payload Structures for each command ***/
typedef struct StructCmd_SetSync {
	StructPayloadHdr header;
	uint8_t tract;
	uint8_t sync_type;
} StructCmd_SetSync;

#pragma pack(pop)

typedef struct E1Proto {
	GQueue *out_queue;		/* Output packets queue */
	GQueue *in_queue;		/* Input packets queue */
	StructPkt *curr_out;		/* Current output packet */
	StructPkt *curr_in;		/* Current input packet*/
	GSocket *socket;		/* */
	GSocketAddress *dst_addr;	/* Destination address */
	GMutex *mutex;
} E1Proto;

gboolean init_proto(E1Proto*, E1Config*);
void deinit_proto(E1Proto*);
StructPkt *init_pkt(void* payload, int size);
StructPkt *read_pkt_from_socket(GSocket*, GSocketAddress*);
void free_pkt(StructPkt*);

/* Functions for internal use only */
static gboolean send_pkt(GSocket*, GSocketAddress*, StructPkt*);
static StructPkt *new_empty_pkt();

/* Test functions */
gboolean test_send_pkt(E1Proto*);

#endif // CONFIG_H_
