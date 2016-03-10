#include <stdlib.h>
#include <syslog.h>
#include <glib.h>
#include <gio/gio.h>
#include <netinet/in.h>
#include <string.h>

#include "../daemon/protocol.h"
#include "../daemon/debug.h"

void send_reply(struct_e1_proto *proto, struct_payload_hdr hdr)
{
	hdr.type = PKT_TYPE_REPLY;
	struct Reply {
		struct_payload_hdr hdr;
		uint8_t err_code;
	} reply;
	reply.hdr = hdr;
	reply.err_code = 1;

	send_pkt(proto, &reply, sizeof(reply));
}

void callback(struct_e1_proto *proto, uint8_t event, uint8_t *payload, uint8_t size)
{
	struct_payload_hdr hdr;
	if (get_pkt_header_from_payload(&hdr, payload, size) == FALSE) {
		LOGE("Getting a packet header failed");
		return;
	} else {
		LOGD("seq ----> %d", hdr.seq);
		LOGD("type ----> %d", hdr.type);
		LOGD("cmd_type ----> %d", hdr.cmd_type);
	}

	switch (event) {
		case EVENT_RECV_PKT:
		LOGD("EVENT_RECV_PKT");
		break;
		case EVENT_REQUEST:
		LOGD("EVENT_REQUEST");
		send_reply(proto, hdr);
		break;
		case EVENT_REPLY:
		LOGD("EVENT_REPLY");
		break;
		case EVENT_SEND_FAIL:
		LOGD("EVENT_SEND_FAIL");
		break;
		default:
		LOGW("Unknown event received -> %d", event);
	}
}

gboolean readFromSock(GIOChannel *source, GIOCondition cond, gpointer data)
{
	syslog(LOG_ERR, "readFromSock!");
	GError *error = NULL;
	GSocket *socket = (GSocket*)data;
	GSocketAddress *gsockaddr_2;

	struct sockaddr_in sockaddr_2;
	sockaddr_2.sin_family = AF_INET;
	sockaddr_2.sin_port = htons(28960);
	inet_aton("192.168.0.1", &sockaddr_2.sin_addr.s_addr);

	gsockaddr_2 = g_socket_address_new_from_native(&sockaddr_2, sizeof(sockaddr_2));

	/***********************************************/
	struct_pkt *pkt = read_pkt_from_socket(socket, gsockaddr_2);
	if (pkt == NULL) {
		free_pkt(pkt);
		return FALSE;
	}

	syslog(LOG_ERR, "pkt->magic -> 0x%.2x", pkt->magic);
	syslog(LOG_ERR, "pkt->version -> %d", pkt->version);
	syslog(LOG_ERR, "pkt->pkt_size -> %d", pkt->pkt_size);


	struct_set_sync set_sync;
	memcpy(&set_sync, pkt->serialized_payload, pkt->pkt_size);

	syslog(LOG_ERR, "tract -> %d", set_sync.tract);
	syslog(LOG_ERR, "sync_type -> %d", set_sync.sync_type);

	free_pkt(pkt);
	return TRUE;
}

int main()
{
	struct_e1_proto proto;
	struct_e1_config cfg;

	openlog("test_e1", LOG_CONS, LOG_DAEMON);
	syslog(LOG_INFO, "Starting test_e1");

	cfg.udp_port = 28960;
	cfg.src_addr = "192.168.0.2";
	cfg.dst_addr = "192.168.0.1";

	/* Initialization */
	if (init_proto(&proto, &cfg) == FALSE) {
		LOGE("Init failed!");
		return -2;
	}

	register_callback(&proto, callback);

	/* Send msg */
	//test_send_pkt(&proto);
	while (1) {

	}

	deinit_proto(&proto);

	return 0;
}