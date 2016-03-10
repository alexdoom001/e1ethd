#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <netinet/in.h>

#include "protocol.h"
#include "debug.h"
#include "commands.h"

gboolean init_proto(struct_e1_proto *proto, struct_e1_config *cfg)
{
	LOGD(">>>");

	proto->out_queue = NULL;
	proto->curr_out = NULL;
	proto->socket = NULL;
	proto->dst_addr = NULL;
	proto->loop = NULL;
	proto->channel = NULL;
	proto->thread = NULL;
	proto->callback = NULL;
	proto->curr_seq = 0;
	proto->timer = 0;
	proto->resend_num = 0;

	GError *error;

	g_mutex_init(&proto->mutex);
	g_mutex_init(&proto->callback_mutex);

	proto->out_queue = g_queue_new();
	if (proto->out_queue == NULL) {
		LOGE("Creating new out queue failed");
		return FALSE;
	}

	/* Create socket */
	proto->socket = g_socket_new(
			G_SOCKET_FAMILY_IPV4,
			G_SOCKET_TYPE_DATAGRAM,
			G_SOCKET_PROTOCOL_UDP,
			&error
			);

	if (proto->socket == NULL) {
		LOGE("Create socket failed -> %s", error->message);
		return FALSE;
	}

	GSocketAddress *gsockaddr;
	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(cfg->udp_port);
	inet_aton(cfg->src_addr, &sockaddr.sin_addr.s_addr);

	gsockaddr = g_socket_address_new_from_native(&sockaddr, sizeof(sockaddr));

	if (g_socket_bind(proto->socket, gsockaddr, TRUE, &error) == FALSE) {
		LOGE("Bind socket failed -> %s", error->message);
		return FALSE;
	}

	/* Create destination address structure */
	struct sockaddr_in sockaddr_dst;

	sockaddr_dst.sin_family = AF_INET;
	sockaddr_dst.sin_port = htons(cfg->udp_port);
	inet_aton(cfg->dst_addr, &sockaddr_dst.sin_addr.s_addr);

	proto->dst_addr = g_socket_address_new_from_native(&sockaddr_dst, sizeof(sockaddr_dst));

	/* Start processing thread */
	proto->loop = g_main_loop_new(NULL, FALSE);
	if (proto->loop == NULL) {
		LOGE("Creating main loop failed");
		return FALSE;
	}

	int fd = g_socket_get_fd(proto->socket);
	proto->channel = g_io_channel_unix_new(fd);
	if (proto->channel == NULL) {
		LOGE("Creating channel failed");
		return FALSE;
	}

	proto->thread = g_thread_new(NULL, (GThreadFunc)start_process_thread, proto);
	if (proto->thread == NULL) {
		LOGE("Starting receive thread failed");
		return FALSE;
	}

	LOGD("<<<");
	return TRUE;
}

void deinit_proto(struct_e1_proto *proto)
{
	LOGD(">>>");

	g_mutex_lock(&proto->mutex);

	if (proto->out_queue != NULL) {
		struct_pkt *next_pkt = g_queue_pop_head(proto->out_queue);

		while (next_pkt != NULL) {
			free_pkt(next_pkt);
			next_pkt = g_queue_pop_head(proto->out_queue);
		}

		g_queue_free(proto->out_queue);
	}

	if (proto->curr_out != NULL) free_pkt(proto->curr_out);
	if (proto->socket != NULL) g_object_unref(proto->socket);
	if (proto->dst_addr != NULL) g_object_unref(proto->dst_addr);
	if (proto->loop != NULL) {
		if (g_main_loop_is_running(proto->loop)) g_main_loop_quit(proto->loop);
		g_main_loop_unref(proto->loop);
	}
	if (proto->thread != NULL) {
		/* Thread will exit after g_main_loop_quit */
		g_thread_unref(proto->thread);
	}
	if (proto->channel != NULL) g_io_channel_unref(proto->channel);
	if (proto->timer != 0) {
		g_source_remove(proto->timer);
	}
	g_mutex_clear(&proto->callback_mutex);

	/* TODO: unlock or not? */
	//g_mutex_unlock(&proto->mutex);

	g_mutex_clear(&proto->mutex);

	LOGD("<<<");
}

/*
 * Name: register_callback
 * Description: Register callback function, that will be called when there is an event
 * Arguments: proto - pointer to main proto structure
 *                    callback - pointer to callback function
 * Returns: None
 */
void register_callback(struct_e1_proto *proto, void *callback)
{
	LOGD(">>>");

	g_mutex_lock(&proto->callback_mutex);

	proto->callback = callback;

	g_mutex_unlock(&proto->callback_mutex);

	LOGD("<<<");
}

/*
 * Name: run_callback_thread (Internal use only)
 * Description: Main function for running callbacks
 * Arguments: proto - pointer to main proto structure
 *            event - event code
 *            pkt - pointer to the packet
 * Returns: None
 */
static void run_callback_thread(struct_e1_proto *proto, uint8_t event, struct_pkt *pkt)
{
	LOGD(">>>");

	StructCallbackData *data = (StructCallbackData*)malloc(sizeof(StructCallbackData));
	data->proto = proto;
	data->event = event;

	data->payload = (uint8_t*)malloc(sizeof(uint8_t) * pkt->pkt_size);

	memcpy(data->payload, pkt->serialized_payload, pkt->pkt_size);

	data->payload_size = pkt->pkt_size;

	GThread *thread  = g_thread_new(NULL, (GThreadFunc)run_callback, (void*)data);
	g_thread_unref(thread);

	LOGD("<<<");
}

/*
 * Name: run_callback (Internal use only)
 * Description: Call registred callback function
 * Arguments: data - pointer to StructCallbackData structure
 * Returns: None
 */
static GThreadFunc run_callback(void *data)
{
	LOGD(">>>");

	StructCallbackData *call_data = (StructCallbackData*)data;

	g_mutex_lock(&call_data->proto->callback_mutex);

	if (call_data->proto->callback == NULL) {
		LOGW("callback is not registered");
	} else {
		call_data->proto->callback(call_data->proto, call_data->event, call_data->payload, call_data->payload_size);
	}

exit:
	g_mutex_unlock(&call_data->proto->callback_mutex);

	free(call_data->payload);
	free(data);

	LOGD("<<<");
}

/*
 * Name: start_process_thread (Internal use only)
 * Description: Starts thread with event loop for send/receive packets (function is for internal use)
 * Arguments: proto - pointer to main proto structure
 * Returns: None
 */
static GThreadFunc start_process_thread(gpointer data)
{
	LOGD(">>>");

	struct_e1_proto *proto = (struct_e1_proto*)data;
	guint source = g_io_add_watch(proto->channel, G_IO_IN, (GIOFunc)process_func, data);

	g_main_loop_run(proto->loop);

	LOGD("<<<");
}

/*
 * Name: process_func (Internal use only)
 * Description: Function running in proto->thread, 
 *              Function is called every time when data in proto->socket is available for reading
 * Arguments: proto - pointer to main proto structure
 * Returns: None
 */
static GThreadFunc process_func(GIOChannel *source, GIOCondition cond, gpointer data)
{
	LOGD(">>>");

	struct_e1_proto *proto = (struct_e1_proto*)data;

	g_io_add_watch(proto->channel, G_IO_IN, (GIOFunc)process_func, data);

	struct_pkt *pkt = read_pkt_from_socket(proto->socket, proto->dst_addr);
	if (pkt == NULL) {
		LOGE("Reading packet failed");
		return;
	}

	//run_callback_thread(proto, EVENT_RECV_PKT, pkt);

	/* Parse packet */
	struct_payload_hdr hdr = get_pkt_header(pkt);

	switch (hdr.type) {
		case PKT_TYPE_REQUEST:
			/* Construct and send reply (without queue) */
			LOGD("PKT_TYPE_REQUEST");
			process_request(proto, pkt, hdr);
			break;
		case PKT_TYPE_REPLY:
			LOGD("PKT_TYPE_REPLY");
			process_reply(proto, pkt, hdr);
			break;
		default: {
			LOGW("Unknown received packet type -> %d", hdr.type);
		}
	}

	free_pkt(pkt);

	LOGD("<<<");
}

/*
 * Name: process_request (Internal use only)
 * Description: Function will be called in processing thread when request packet is received
 * Arguments: proto - pointer to main proto structure
 *            recv_pkt - pointer to the received packet
 *            recv_hdr - received packet's header
 * Returns: None
 */
static void process_request(struct_e1_proto *proto, struct_pkt *recv_pkt, struct_payload_hdr recv_hdr)
{
	LOGD(">>>");

	/* TODO: fix stub */

	run_callback_thread(proto, EVENT_REQUEST, recv_pkt);

	LOGD("<<<");
}

/*
 * Name: process_reply (Internal use only)
 * Description: Function will be called in processing thread when reply packet is received
 * Arguments: proto - pointer to main proto structure
 *            recv_pkt - pointer to the received packet
 *            recv_hdr - received packet's header
 * Returns: None
 */
static void process_reply(struct_e1_proto *proto, struct_pkt *recv_pkt, struct_payload_hdr recv_hdr)
{
	LOGD(">>>");

	g_mutex_lock(&proto->mutex);

	struct_payload_hdr curr_hdr = get_pkt_header(recv_pkt);

	if ((curr_hdr.seq == recv_hdr.seq) && (curr_hdr.cmd_type == recv_hdr.cmd_type)) {
		remove_timeout(proto);

		run_callback_thread(proto, EVENT_REPLY, recv_pkt);

		free_pkt(proto->curr_out);

		send_next_pkt(proto);
	}


exit:
	g_mutex_unlock(&proto->mutex);

	LOGD("<<<");
}

/*
 * Name: new_empty_pkt (Internal use only)
 * Description: Creates empty packet (function is for internal use)
 * Arguments: None
 * Returns: Pointer to the new empty packet, NULL otherwise
 */
static struct_pkt *new_empty_pkt()
{
	struct_pkt *pkt = (struct_pkt*)malloc(sizeof(pkt) + sizeof(pkt->serialized_payload));
	pkt->serialized_payload = NULL;
	return pkt;
}

/*
 * Name: get_next_seq_h
 * Description: Returns sequence number in the host byte order
 * Arguments: None
 * Returns: sequence number [1, UINT32_MAX]
 */
uint32_t get_next_seq_h(struct_e1_proto *proto)
{
	g_mutex_lock(&proto->mutex);

	if (proto->curr_seq == UINT32_MAX) {
		proto->curr_seq = 1;
	} else {
		proto->curr_seq++;
	}

	g_mutex_unlock(&proto->mutex);

	return proto->curr_seq;
}

/*
 * Name: get_next_seq_h
 * Description: Returns sequence number in the network byte order
 * Arguments: None
 * Returns: sequence number [1, UINT32_MAX]
 */
uint32_t get_next_seq_n(struct_e1_proto *proto)
{
	uint32_t seq = get_next_seq_h(proto);

	seq = htonl(seq);

	return seq;
}

/*
 * Name: free_pkt
 * Description: Frees memory allocated for packet
 * Arguments: pkt - struct_pkt pointer
 * Returns: None
 */
static void free_pkt(struct_pkt* pkt)
{
	if (pkt == NULL) return;

	if (pkt->serialized_payload != NULL) free(pkt->serialized_payload);

	free(pkt);
}

/*
 * Name: init_pkt
 * Description: Creates and initializes new packet from payload structure
 * Arguments: payload - pointer to command structure
 *            size - size of payload structure
 * Returns: Pointer to the created packet if success, NULL otherwise
 */
static struct_pkt *init_pkt(void *payload, int size)
{
	struct_pkt *pkt = new_empty_pkt();
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

uint8_t serialize_pkt(struct_pkt *pkt, uint8_t *buf)
{
	struct_pkt *new_pkt = new_empty_pkt();
	memcpy(new_pkt, pkt, sizeof(pkt));

	uint8_t size = sizeof(pkt) + pkt->pkt_size;

	new_pkt->magic = htons(pkt->magic);
	new_pkt->version = htons(pkt->version);
	new_pkt->pkt_size = htonl(pkt->pkt_size);

	/* Copy pkt header */
	memcpy(buf, new_pkt, sizeof(pkt));

	/* Copy payload */
	memcpy(buf + sizeof(pkt), pkt->serialized_payload, pkt->pkt_size);

	free_pkt(new_pkt);
	return size;
}

/*
 * Name: send_pkt (Internal use only)
 * Description: Sends the packet to the destination point (function is for internal use)
 * Arguments: sock - pointer to the UDP socket
 *            addr - pointer to the destination address structure
 *            pkt - pointer to the packet to be sent
 * Returns: TRUE if success, FALSE otherwise
 */
gboolean send_pkt_now(struct_e1_proto *proto, GSocket *sock, GSocketAddress *addr, struct_pkt *pkt)
{
	LOGD(">>>");

	struct_payload_hdr hdr = get_pkt_header(pkt);
	if (hdr.type == PKT_TYPE_REQUEST) proto->curr_out = pkt;

	GError *error;

	uint32_t size = sizeof(pkt) + pkt->pkt_size;
	uint8_t *buf = malloc(size * sizeof(uint8_t));

	serialize_pkt(pkt, buf);

	if (g_socket_send_to(sock, addr, buf, size, NULL, &error) == -1) {
		LOGE("Send packet failed: %s", error->message);
		free(buf);
		return FALSE;
	}

	if (proto->timer == 0) {
		if (hdr.type == PKT_TYPE_REQUEST ) {
			LOGD("Create timer");
			proto->timer = g_timeout_add(RESEND_INTERVAL, (GSourceFunc)timeout_func, proto);
		}
	}

	free(buf);

	LOGD("<<<");
	return TRUE;
}

/*
 * Name: remove_timeout (Internal use only)
 * Description: Removes timeout source from main proto structure
 * Arguments: None
 * Returns: None
 */
static void remove_timeout(struct_e1_proto *proto)
{
	LOGD(">>>");

	g_source_remove(proto->timer);
	proto->timer = 0;
	proto->resend_num = 0;

	LOGD("<<<");
}

/*
 * Name: timeout_func (Internal use only)
 * Description: Function is called at regular intervals after sending a packet,
 *              until a reply packet is not received
 * Arguments: data - pointer to a proto structures
 * Returns: FALSE if reply pkt is received or resend limit is out, TRUE otherwise
 */
static GSourceFunc timeout_func(gpointer data)
{
	LOGD(">>>");

	struct_e1_proto *proto = (struct_e1_proto*)data;

	gboolean ret;

	g_mutex_lock(&proto->mutex);

	LOGD("resend count = %d", proto->resend_num);

	if (proto->resend_num <= RESEND_LIMIT) {
		send_pkt_now(proto, proto->socket, proto->dst_addr, proto->curr_out);
		proto->resend_num++;
		ret = TRUE;
	} else {
		LOGD("EVENT_SEND_FAIL");
		remove_timeout(proto);
		run_callback_thread(proto, EVENT_SEND_FAIL, proto->curr_out);
		ret = FALSE;
		free_pkt(proto->curr_out);
		send_next_pkt(proto);
	}

	LOGD("<<<");

	g_mutex_unlock(&proto->mutex);

	return ret;
}

/*
 * Name: get_pkt_header
 * Description: Gets payload header from pkt (Internal use)
 * Arguments: pkt - pointer to pkt structure
 * Returns: struct_payload_hdr value
 */
static struct_payload_hdr get_pkt_header(const struct_pkt *pkt)
{
	struct_payload_hdr hdr;

	memcpy(&hdr, pkt->serialized_payload, sizeof(struct_payload_hdr));

	return hdr;
}

/*
 * Name: get_pkt_header_from_payload
 * Description: Gets payload header from serialized payload
 * Arguments: hdr - pointer to the destination header structure
 *            payload - pointer to the serialized payload
 *            size - payload size
 * Returns: TRUE - if success, FALSE otherwise
 */
gboolean get_pkt_header_from_payload(struct_payload_hdr *hdr, uint8_t *payload, uint8_t size)
{
	if ((hdr == NULL) || (payload == NULL) || (size < sizeof(struct_payload_hdr))) {
		return FALSE;
	}

	memcpy(hdr, payload, sizeof(struct_payload_hdr));

	return TRUE;
}

/*
 * Name: get_reply_header_from_payload
 * Description: Gets a reply header from serialized payload
 * Arguments: hdr - pointer to the destination header structure
 *            payload - pointer to the serialized payload
 *            size - payload size
 * Returns: TRUE - if success, FALSE otherwise
 */
gboolean get_reply_header_from_payload(struct_reply_hdr *hdr, uint8_t *payload, uint8_t size)
{
	if ((hdr == NULL) || (payload == NULL) || (size < sizeof(struct_reply_hdr))) {
		return FALSE;
	}

	memcpy(hdr, payload, sizeof(struct_reply_hdr));

	return TRUE;
}

/*
 * Name: read_pkt_from_socket
 * Description: Reads deserialize data from socket, when it's available (function is for internal use)
 * Arguments: socket - pointer to the UDP socket
 *            sock_addr - pointer to the destination address structure
 * Returns: Pointer to the received packet if success, NULL otherwise
 */
static struct_pkt *read_pkt_from_socket(GSocket *socket, GSocketAddress *sock_addr)
{
	LOGD(">>>");

	GError *error = NULL;
	struct_pkt *pkt = new_empty_pkt();
	if (pkt == NULL) {
		return NULL;
	}

	gsize available_bytes = g_socket_get_available_bytes(socket);

	uint8_t *buf = (uint8_t*)malloc(available_bytes * sizeof(uint8_t));
	if (g_socket_receive_from(socket, &sock_addr, (gchar*)buf, available_bytes, NULL, &error) == -1) {
		LOGE("Read packet failed: %s", error->message);
		free(buf);
		return NULL;
	}

	memcpy(pkt, buf, sizeof(pkt));

	/*** TODO: Check magic, pkt_size and protocol ver ***/

	pkt->serialized_payload = malloc(pkt->pkt_size * sizeof(uint8_t));

	pkt->magic = ntohs(pkt->magic);
	pkt->version = ntohs(pkt->version);
	pkt->pkt_size = ntohl(pkt->pkt_size);

	memcpy(pkt->serialized_payload, buf + sizeof(pkt), pkt->pkt_size);

	free(buf);

	LOGD("<<<");
	return pkt;
}

/*
 * Name: send_pkt
 * Description: Send packet. If there is a packet in processing add the packet to the queue.
 * Arguments: proto - main proto structure
 *            pkt - pointer to the packet to be sent
 * Returns: TRUE if success, FALSE otherwise
 */
gboolean send_pkt(struct_e1_proto *proto, void *data, int len)
{
	LOGD(">>>");

	gboolean ret = FALSE;

	if (proto == NULL) {
		return ret;
	}

	/* Create new pkt */
	struct_pkt *pkt = init_pkt(data, len);
	if (pkt == NULL) {
		return ret;
	}

	g_mutex_lock(&proto->mutex);

	if (pkt == NULL) {
		LOGD("pkt is NULL");
		goto exit;
	}

	struct_payload_hdr hdr;
	get_pkt_header_from_payload(&hdr, data, len);

	if (hdr.type == PKT_TYPE_REPLY) {
		ret = send_pkt_now(proto, proto->socket, proto->dst_addr, pkt);
		goto exit;
	}

	if (proto->curr_out == NULL) {
		LOGD("curr_out is NULL. Sending pkt");
		ret = send_pkt_now(proto, proto->socket, proto->dst_addr, pkt);
		goto exit;
	}

	LOGD("Insert pkt to the queue");
	g_queue_push_tail(proto->out_queue, pkt);
	ret = TRUE;

exit:

	LOGD("<<<");

	g_mutex_unlock(&proto->mutex);

	return ret;

}

/*
 * Name: send_next_pkt (Internal use only)
 * Description: Pops packet from an out queue and sends it
 * Arguments: proto - pointer to the main proto structure
 * Returns: None
 */
static void send_next_pkt(struct_e1_proto *proto)
{
	LOGD(">>>");

	struct_pkt *pkt = g_queue_pop_head(proto->out_queue);
	if (pkt != NULL) {
		send_pkt_now(proto, proto->socket, proto->dst_addr, pkt);
	} else {
		proto->curr_out = NULL;
	}

	LOGD("<<<");
}


/* Test functions */
gboolean test_send_pkt(struct_e1_proto *proto)
{
	struct_set_sync set_sync;
	set_sync.hdr.type = PKT_TYPE_REQUEST;
	set_sync.hdr.seq = get_next_seq_n(proto);
	set_sync.hdr.cmd_type = 0x01;
	set_sync.tract = 2;
	set_sync.sync_type = 3;

	if (send_pkt(proto, &set_sync, sizeof(set_sync)) == FALSE) {
		LOGE("Send pkt failed!");
	}

}
