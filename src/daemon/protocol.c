#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

#include "protocol.h"

gboolean init_proto(E1Proto *proto, E1Config *cfg) {
	/*** TODO: Init mutex ***/

	GError *error;

	/*** Create socket ***/
	proto->socket = g_socket_new(
			G_SOCKET_FAMILY_IPV4,
			G_SOCKET_TYPE_DATAGRAM,
			G_SOCKET_PROTOCOL_UDP,
			&error
			);

	if (proto->socket == NULL) {
		syslog(LOG_ERR, "Create socket failed -> %s", error->message);
		return FALSE;
	}

	GSocketAddress *gsockaddr;
	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(cfg->udp_port);
	inet_aton(cfg->src_addr, &sockaddr.sin_addr.s_addr);

	gsockaddr = g_socket_address_new_from_native(&sockaddr, sizeof(sockaddr));

	if (g_socket_bind(proto->socket, gsockaddr, TRUE, &error) == FALSE) {
		syslog(LOG_ERR, "Bind socket failed -> %s", error->message);
		return FALSE;
	}

	/*** Create destination address structure ***/
	struct sockaddr_in sockaddr_dst;

	sockaddr_dst.sin_family = AF_INET;
	sockaddr_dst.sin_port = htons(cfg->udp_port);
	inet_aton(cfg->dst_addr, &sockaddr_dst.sin_addr.s_addr);

	proto->dst_addr = g_socket_address_new_from_native(&sockaddr_dst, sizeof(sockaddr_dst));

	return TRUE;
}

void deinit_proto(E1Proto *proto) {
	if (proto->out_queue != NULL) g_queue_free(proto->out_queue);
	if (proto->in_queue != NULL) g_queue_free(proto->in_queue);
	if (proto->curr_out != NULL) free_pkt(proto->curr_out);
	if (proto->curr_in != NULL) free_pkt(proto->curr_in);
	if (proto->socket != NULL) g_object_unref(proto->socket);
	if (proto->dst_addr != NULL) g_object_unref(proto->dst_addr);
	if (proto->mutex != NULL) g_object_unref(proto->mutex);
}

/***********************************************************************************/
/*** Name: new_empty_pkt
/*** Description: Creates empty packet (function is for internal use)
/*** Arguments: None
/*** Returns: Pointer to the new empty packet, NULL otherwise
/***********************************************************************************/
static StructPkt *new_empty_pkt() {
	StructPkt *pkt = (StructPkt*)malloc(sizeof(pkt) + sizeof(pkt->serialized_payload));
	return pkt;
}

/***********************************************************************************/
/*** Name: free_pkt
/*** Description: Frees memory allocated for packet
/*** Arguments: pkt - StructPkt pointer
/*** Returns: None
/***********************************************************************************/
void free_pkt(StructPkt* pkt) {
	free(pkt->serialized_payload);
	free(pkt);
}

/***********************************************************************************/
/*** Name: init_pkt
/*** Description: Creates and initializes new packet from payload structure
/*** Arguments: payload - pointer to command structure
/***            size - size of payload structure
/*** Returns: Pointer to the created packet if success, NULL otherwise
/***********************************************************************************/
StructPkt *init_pkt(void *payload, int size) {
	StructPkt *pkt = new_empty_pkt();
	if (pkt == NULL) {
		return NULL;
	}

	pkt->magic = MAGIC_VAL;
	pkt->version = PROTO_VER;
	pkt->pkt_size = size;

	pkt->serialized_payload = malloc(size * sizeof(uint8_t));
	if (pkt->serialized_payload == NULL) {
		free(pkt);
		return NULL;
	}

	memcpy(pkt->serialized_payload, payload, size);

	return pkt;
}

/***********************************************************************************/
/*** Name: send_pkt
/*** Description: Sends the packet to the destination point (function is for internal use)
/*** Arguments: sock - pointer to the UDP socket
/***            addr - pointer to the destination address structure
/***            pkt - pointer to the packet to be sent
/*** Returns: TRUE if success, FALSE otherwise
/***********************************************************************************/
static gboolean send_pkt(GSocket *sock, GSocketAddress *addr, StructPkt *pkt) {
	GError *error;
	uint8_t *buf;

	uint8_t size = sizeof(pkt) + pkt->pkt_size;
	buf = malloc(size * sizeof(uint8_t));

	/* Copy pkt header */
	memcpy(buf, pkt, sizeof(pkt));

	/* Copy payload */
	memcpy(buf + sizeof(pkt), pkt->serialized_payload, pkt->pkt_size);

	if (g_socket_send_to(sock, addr, buf, size, NULL, &error) == -1) {
		syslog(LOG_ERR, "Send packet failed: %s", error->message);
		free(buf);
		return FALSE;
	}

	free(buf);
	return TRUE;
}

/***********************************************************************************/
/*** Name: read_pkt_from_socket
/*** Description: Reads deserialize data from socket, when it's available (function is for internal use)
/*** Arguments: socket - pointer to the UDP socket
/***            sock_addr - pointer to the destination address structure
/*** Returns: Pointer to the received packet if success, NULL otherwise
/***********************************************************************************/
StructPkt *read_pkt_from_socket(GSocket *socket, GSocketAddress *sock_addr) {
	GError *error = NULL;
	StructPkt *pkt = new_empty_pkt();
	if (pkt == NULL) {
		return NULL;
	}

	gsize available_bytes = g_socket_get_available_bytes(socket);

	uint8_t *buf = (uint8_t*)malloc(available_bytes * sizeof(uint8_t));
	if (g_socket_receive_from(socket, &sock_addr, (gchar*)buf, available_bytes, NULL, &error) == -1) {
		syslog(LOG_ERR, "Read packet failed: %s", error->message);
		free(buf);
		return NULL;
	}

	memcpy(pkt, buf, sizeof(pkt));

	/*** TODO: Check magic, pkt_size and protocol ver ***/

	pkt->serialized_payload = malloc(pkt->pkt_size * sizeof(uint8_t));

	memcpy(pkt->serialized_payload, buf + sizeof(pkt), pkt->pkt_size);

	free(buf);
	return pkt;
}


/*** Test functions ***/
gboolean test_send_pkt(E1Proto *proto) {
	StructCmd_SetSync set_sync;
	set_sync.header.type = PKT_TYPE_REQUEST;
	set_sync.header.seq = 10;
	set_sync.header.cmd_type = 0x01;
	set_sync.tract = 2;
	set_sync.sync_type = 3;

	StructPkt *pkt = init_pkt(&set_sync, sizeof(set_sync));
	if (send_pkt(proto->socket, proto->dst_addr, pkt) == FALSE) {
		syslog(LOG_ERR, "Send pkt failed!");
	}
	free_pkt(pkt);
}
