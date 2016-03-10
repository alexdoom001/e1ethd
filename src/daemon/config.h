#ifndef CONFIG_H_
#define CONFIG_H_ 1

#include <glib.h>
#include <stdint.h>

#define CONF_PATH "/etc/e1ethd.conf"
#define GRP_MAIN "e1ethd"
#define DEFAULT_DST_ADDR	"192.0.2.2"
#define DEFAULT_SRC_ADDR	"192.0.2.3"
#define DEFAULT_UDP_PORT 28960

#define KEY_SRC_ADDR		"src_addr"
#define KEY_DST_ADDR		"dst_addr"
#define KEY_UDP_PORT		"port"
#define KEY_TRACTS		"tracts"
#define KEY_SYNC		"sync"
#define KEY_CODE		"code"
#define KEY_FRAMING		"framing"
#define KEY_CHANNELS		"channels"
#define KEY_VID 		"vid"
#define KEY_SLOT_BEGIN		"slot_begin"
#define KEY_SLOT_END		"slot_end"
#define KEY_HDLC		"hdlc"

#define CFG_SYNC_INNER		"internal"
#define CFG_SYNC_OUTER		"external"

#define CFG_CODE_HDB3		"hdb3"
#define CFG_CODE_AMI		"ami"

#define CFG_FRAME_G704		"g704"
#define CFG_FRAME_G704_NO_SRC	"g704-no-crc"
#define CFG_FRAME_UNFRAMED	"unframed"

#define CFG_MASK_LOS		"los"
#define CFG_MASK_POS_SLIP	"positive_slip"
#define CFG_MASK_NEG_SLIP	"negative_slip"

#define CFG_HDLC_ETH		"cisco-hdlc-ethernet"
#define CFG_HDLC_IP		"cisco-hdlc-ip"

#define GRP_DIGIT		8
#define GRP_SEPARATOR		"_"

typedef struct struct_e1_channel {
	uint8_t id;
	uint8_t vid;
	uint8_t slot_begin;
	uint8_t slot_end;
	uint8_t hdlc;
} struct_e1_channel;

typedef struct struct_e1_tract {
	uint8_t id;
	uint8_t sync;
	uint8_t code;
	uint8_t framing;
	gsize ch_num;
	struct_e1_channel *channels;
} struct_e1_tract;

typedef struct struct_e1_config {
	gchar *src_addr;
	gchar *dst_addr;
	int udp_port;
	gsize tr_num;
	struct_e1_tract *tracts;
} struct_e1_config;

gboolean read_config(struct_e1_config *config, char *config_file);
void free_config(struct_e1_config *config);
static void free_e1_tract(struct_e1_tract *config);
static gboolean parse_tract(GKeyFile *key_file, gint grp_id, GError *err, struct_e1_tract *tract);
static gboolean parse_channel(GKeyFile *key_file, gchar *tract_str, gint ch_id, GError *err, struct_e1_channel *channel);

#endif // CONFIG_H_
