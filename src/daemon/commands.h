#ifndef COMMANDS_H_
#define COMMANDS_H_ 1

#define REQ_OFFSET		0x80

#define E1_RESET		0x00
#define E1_SET_SYNC		0x01
#define E1_SET_CODE		0x02
#define E1_SET_FRAMING		0x03
#define E1_NOTIFY		0x04
#define E1_ADD_CHANNEL		0x05
#define E1_DEL_CHANNEL		0x06
#define E1_RESET_CHANNEL_STAT	0x07

#define E1_REQ_VERSION		0x80
#define E1_REQ_SYNC		(REQ_OFFSET | E1_SET_SYNC)
#define E1_REQ_CODE		(REQ_OFFSET | E1_SET_CODE)
#define E1_REQ_FRAMING		(REQ_OFFSET | E1_SET_FRAMING)
#define E1_REQ_NOTIFY		(REQ_OFFSET | E1_NOTIFY)
#define E1_REQ_CHANNEL		(REQ_OFFSET | E1_ADD_CHANNEL)
#define E1_REQ_CHANNEL_STAT	(REQ_OFFSET | E1_RESET_CHANNEL_STAT)

/* Syncronization types for E1_SET_SYNC */
#define SYNC_INNER		0x00
#define SYNC_OUTER		0x01

/* Coding types for E1_SET_CODE */
#define CODE_HDB3		0x00
#define CODE_AMI		0x01

/* Framing types for E1_SET_FRAMING */
#define FRAME_G704		0x00
#define FRAME_G704_NO_SRC	0x01
#define FRAME_UNFRAMED		0x02

/* State masks for E1_NOTIFY */
#define MASK_LOS		0x01
#define MASK_POS_SLIP		0x02
#define MASK_NEG_SLIP		0x04

/* HDLC types for E1_ADD_CHANNEL */
#define HDLC_ETH		0x00
#define HDLC_IP			0x01

#pragma pack(push, 1)

typedef struct struct_payload_hdr {
	uint8_t type;
	uint32_t seq;
	uint8_t cmd_type;
} struct_payload_hdr;

typedef struct struct_reply_hdr {
	uint8_t type;
	uint32_t seq;
	uint8_t cmd_type;
	uint8_t ret_code;
} struct_reply_hdr;

/*** Payload Structures for each command ***/
/* E1_RESET */
typedef struct struct_reset {
	struct_payload_hdr hdr;
} struct_reset;

/* E1_REQ_VERSION */
typedef struct struct_req_version {
	struct_payload_hdr hdr;
} struct_req_version;

typedef struct struct_req_version_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
	uint8_t version;
} struct_req_version_repl;

/* E1_SET_SYNC */
typedef struct struct_set_sync {
	struct_payload_hdr hdr;
	uint8_t tract;
	uint8_t sync_type;
} struct_set_sync;

typedef struct struc_set_sync_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
} struc_set_sync_repl;

/* E1_SET_CODE */
typedef struct struct_set_code {
	struct_payload_hdr hdr;
	uint8_t tract;
	uint8_t code_type;
} struct_set_code;

typedef struct struct_set_code_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
} struct_set_code_repl;

/* E1_SET_FRAMING */
typedef struct struct_set_framing {
	struct_payload_hdr hdr;
	uint8_t tract;
	uint8_t frame_type;
} struct_set_framing;

typedef struct struct_set_framing_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
} struct_set_framing_repl;

/* E1_NOTIFY */
typedef struct struct_notify {
	struct_payload_hdr hdr;
	uint8_t tract;
	uint8_t mask;
} struct_notify;

typedef struct struct_notify_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
} struct_notify_repl;

/* E1_ADD_CHANNEL */
typedef struct struct_add_channel {
	struct_payload_hdr hdr;
	uint8_t channel;
	uint16_t vid;
	uint8_t tract;
	uint8_t slot_begin;
	uint8_t slot_end;
	uint8_t hdlc;
} struct_add_channel;

typedef struct struct_add_channel_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
} struct_add_channel_repl;

/* E1_DEL_CHANNEL */
typedef struct struct_del_channel {
	struct_payload_hdr hdr;
	uint8_t channel;
} struct_del_channel;

typedef struct struct_del_channel_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
} struct_del_channel_repl;

/* E1_RESET_CHANNEL_STAT */
typedef struct struct_reset_channel_stat {
	struct_payload_hdr hdr;
	uint8_t channel;
} struct_reset_channel_stat;

typedef struct struct_reset_channel_stat_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
} struct_reset_channel_stat_repl;

/* E1_REQ_SYNC */
typedef struct struct_req_sync {
	struct_payload_hdr hdr;
	uint8_t tract;
} struct_req_sync;

typedef struct struct_req_sync_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
	uint8_t sync;
} struct_req_sync_repl;

/* E1_REQ_CODE */
typedef struct struct_req_code {
	struct_payload_hdr hdr;
	uint8_t tarct;
} struct_req_code;

typedef struct struct_req_code_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
	uint8_t code_type;
} struct_req_code_repl;

/* E1_REQ_FRAMING */
typedef struct struct_req_framing {
	struct_payload_hdr hdr;
	uint8_t tract;
} struct_req_framing;

typedef struct struct_req_framing_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
	uint8_t frame_type;
} struct_req_framing_repl;

/* E1_REQ_NOTIFY */
typedef struct struct_req_notify {
	struct_payload_hdr hdr;
	uint8_t tract;
} struct_req_notify;

typedef struct struct_req_notify_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
	uint8_t mask;
} struct_req_notify_repl;

/* E1_REQ_CHANNEL */
typedef struct struct_req_channel {
	struct_payload_hdr hdr;
	uint8_t channel;
} struct_req_channel;

typedef struct struct_req_channel_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
	uint8_t flag;
	uint16_t vid;
	uint8_t tract;
	uint8_t slot_begin;
	uint8_t slot_end;
	uint8_t hdlc;
} struct_req_channel_repl;

/* E1_REQ_CHANNEL_STAT */
typedef struct struct_req_channel_stat {
	struct_payload_hdr hdr;
	uint8_t channel;
} struct_req_channel_stat;

typedef struct struct_req_channel_stat_repl {
	struct_payload_hdr hdr;
	uint8_t ret;
	/* TODO: define counters */
} struct_req_channel_stat_repl;

#pragma pack(pop)


#endif /* COMMANDS_H_ */
