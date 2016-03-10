#ifndef PROTO_H_
#define PROTO_H_ 1

#include <glib.h>
#include <gio/gio.h>
#include <stdint.h>

#include "config.h"
#include "commands.h"

#define MAGIC_VAL		0x5a81

#define PROTO_VER		0

#define UDP_PORT		28960

#define PKT_TYPE_REQUEST	0
#define PKT_TYPE_REPLY		1

#define RESEND_INTERVAL		1000
#define RESEND_LIMIT		3

#define RET_SUCCESS	0x00


#pragma pack(push, 1)

/*** Main packet structure ***/
typedef struct struct_pkt {
	uint16_t magic;
	uint16_t version;
	uint32_t pkt_size;
	uint8_t *serialized_payload;
} struct_pkt;

#pragma pack(pop)

typedef struct struct_e1_proto {
	GQueue *out_queue;		/* Output packets queue */
	GQueue *in_queue;		/* Input packets queue */
	struct_pkt *curr_out;		/* Current output packet */
	struct_pkt *curr_in;		/* Current input packet*/
	GSocket *socket;		/* */
	GSocketAddress *dst_addr;	/* Destination address */
	GMutex mutex;
	GMutex callback_mutex;
	GMainLoop *loop;
	GIOChannel *channel;
	GThread *thread;
	void (*callback)();
	uint32_t curr_seq;
	guint timer;
	uint8_t resend_num;
} struct_e1_proto;

typedef struct StructCallbackData {
	struct_e1_proto *proto;
	uint8_t event;
	uint8_t *payload;
	uint8_t payload_size;
} StructCallbackData;

/* Events */
#define EVENT_RECV_PKT		1	/* Emitted when packet is received */
#define EVENT_REPLY		2	/* Emitted when a reply packet for current sent packet is received from addressee */
#define EVENT_REQUEST		3	/* Emitted  when a request packet is received */
#define EVENT_SEND_FAIL		4	/* Emitted  when a reply packet is not received after timeout */


gboolean init_proto(struct_e1_proto*, struct_e1_config*);
void deinit_proto(struct_e1_proto*);
void register_callback(struct_e1_proto*, void*);

uint32_t get_next_seq_h(struct_e1_proto*);
uint32_t get_next_seq_n(struct_e1_proto*);
gboolean send_pkt(struct_e1_proto*, void *data, int size);
gboolean get_pkt_header_from_payload(struct_payload_hdr *hdr, uint8_t *payload, uint8_t size);

/* Functions for internal use only */
static struct_pkt *init_pkt(void* payload, int size);
static void free_pkt(struct_pkt*);
static gboolean send_pkt_now(struct_e1_proto*, GSocket*, GSocketAddress*, struct_pkt*);
static struct_pkt *new_empty_pkt();
static GThreadFunc start_process_thread(gpointer);
static GThreadFunc process_func(GIOChannel*, GIOCondition, gpointer);
static void run_callback_thread(struct_e1_proto*, uint8_t, struct_pkt*);
static GThreadFunc run_callback(void*);
static struct_payload_hdr get_pkt_header(const struct_pkt*);
static void process_request(struct_e1_proto *, struct_pkt *, struct_payload_hdr);
static void process_reply(struct_e1_proto*, struct_pkt*, struct_payload_hdr);
static GSourceFunc timeout_func(gpointer data);
static void remove_timeout(struct_e1_proto*);
static void send_next_pkt(struct_e1_proto*);
static struct_pkt *read_pkt_from_socket(GSocket*, GSocketAddress*);

/* Test functions */
gboolean test_send_pkt(struct_e1_proto*);

#endif // CONFIG_H_
