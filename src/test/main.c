#include <stdlib.h>
#include <syslog.h>
#include <glib.h>
#include <gio/gio.h>
#include <netinet/in.h>
#include <string.h>

#include "../daemon/protocol.h"

gboolean readFromSock(GIOChannel *source, GIOCondition cond, gpointer data) {
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
	StructPkt *pkt = read_pkt_from_socket(socket, gsockaddr_2);
	if (pkt == NULL) {
		free_pkt(pkt);
		return FALSE;
	}

	syslog(LOG_ERR, "pkt->magic -> 0x%.2x", pkt->magic);
	syslog(LOG_ERR, "pkt->version -> %d", pkt->version);
	syslog(LOG_ERR, "pkt->pkt_size -> %d", pkt->pkt_size);


	StructCmd_SetSync set_sync;
	memcpy(&set_sync, pkt->serialized_payload, pkt->pkt_size);

	syslog(LOG_ERR, "tract -> %d", set_sync.tract);
	syslog(LOG_ERR, "sync_type -> %d", set_sync.sync_type);

	free_pkt(pkt);
	return TRUE;
}

int main() {
	openlog("e1ethd", LOG_CONS, LOG_DAEMON);
	syslog(LOG_INFO, "Starting e1_test");

	GMainLoop *loop;
	loop = g_main_loop_new(NULL, FALSE);

	/***********************************************************/
	GError *error = NULL;
	GSocket *socket = g_socket_new(
			G_SOCKET_FAMILY_IPV4,
			G_SOCKET_TYPE_DATAGRAM,
			G_SOCKET_PROTOCOL_UDP,
			&error
			);

	if (socket == NULL) {
		syslog(LOG_ERR, "test: Create socket failed -> %s", error->message);
		return -1;
	}

	GSocketAddress *gsockaddr;
	struct sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(28960);
	inet_aton("192.168.0.2", &sockaddr.sin_addr.s_addr);

	gsockaddr = g_socket_address_new_from_native(&sockaddr, sizeof(sockaddr));

	if (g_socket_bind(socket, gsockaddr, TRUE, &error) == FALSE) {
		syslog(LOG_ERR, "test: Bind socket failed -> %s", error->message);
		return -1;
	}


	int fd = g_socket_get_fd(socket);
	GIOChannel *channel = g_io_channel_unix_new(fd);
	guint source = g_io_add_watch(channel, G_IO_IN, (GIOFunc) readFromSock, socket);
	g_io_channel_unref(channel);


	/***********************************************************/

	g_main_loop_run(loop);

	g_main_loop_unref(loop);

	return 0;
}