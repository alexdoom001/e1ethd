#include <stdlib.h>
#include <syslog.h>
#include <glib.h>
#include <gio/gio.h>
#include <netinet/in.h>
#include <signal.h>

#include "debug.h"
#include "config.h"
#include "protocol.h"
#include "commands.h"

struct_e1_config cfg;
struct_e1_proto proto;

uint32_t curr_seq;

#define RES_NONE	0
#define RES_SEND_FAIL	1
#define RES_CMD_OK	2
#define RES_CMD_FAIL	3
uint8_t curr_res = RES_NONE;

GMutex mutex;
GCond cond;

void process_req(struct_e1_proto *proto, struct_payload_hdr *hdr, uint8_t *payload, uint8_t size)
{
	void *reply;
	uint32_t repl_size;

	if (hdr->cmd_type == E1_NOTIFY) {
		LOGD("E1_NOTIFY");
		struct_notify *notify = (struct_notify*)payload;
		LOGD("tract -> %d", notify->tract);
		LOGD("mask -> 0x%.2x", notify->mask);

		struct_notify_repl *r = (struct_notify_repl*)malloc(sizeof(struct_notify_repl));
		r->hdr.type = PKT_TYPE_REPLY;
		r->hdr.seq = hdr->seq;
		r->hdr.cmd_type = hdr->cmd_type;
		r->ret = RET_SUCCESS;
		reply = r;
		repl_size = sizeof(struct_notify_repl);
	}
	else {
		LOGW("Not processed request -> 0x%.2x", hdr->cmd_type);
		return;
	}

	if (send_pkt(proto, reply, repl_size) == FALSE) {
		LOGE("Sending reply failed");
	}

	free(reply);
}

void process_repl(uint8_t *payload, uint8_t size)
{
	struct_reply_hdr hdr;
	get_reply_header_from_payload(&hdr, payload, size);

	g_mutex_lock(&mutex);

	if (hdr.seq == curr_seq) {
		curr_res = hdr.ret_code == RET_SUCCESS ? RES_CMD_OK : RES_CMD_FAIL;
		g_cond_signal(&cond);
	} else {
		LOGW("An unexpected reply is received, code -> 0x%.2x", hdr.cmd_type);
	}

	/*if (hdr.ret_code != RET_SUCCESS) {
		LOGE("Request 0x%.2x failed, error: 0x%.2x", hdr.cmd_type, hdr.ret_code);
	} else {
		LOGD("Request 0x%.2x success", hdr.cmd_type);
	}*/

	g_mutex_unlock(&mutex);
}

void callback(struct_e1_proto *proto, uint8_t event, uint8_t *payload, uint8_t size)
{
	struct_payload_hdr hdr;
	if (!get_pkt_header_from_payload(&hdr, payload, size)) {
		LOGE("Getting a packet header failed");
	} else {
		LOGD("seq ----> %d", ntohl(hdr.seq));
		LOGD("type ----> 0x%.2x", hdr.type);
		LOGD("cmd_type ----> 0x%.2x", hdr.cmd_type);
	}

	switch (event) {
		case EVENT_RECV_PKT:
		LOGD("EVENT_RECV_PKT");
		break;
		case EVENT_REQUEST:
		LOGD("EVENT_REQUEST");
		process_req(proto, &hdr, payload, size);
		break;
		case EVENT_REPLY:
		LOGD("EVENT_REPLY");
		process_repl(payload, size);
		break;
		case EVENT_SEND_FAIL:
			LOGD("EVENT_SEND_FAIL");
			if (hdr.seq == curr_seq) {
				g_mutex_lock(&mutex);

				curr_res = RES_SEND_FAIL;
				g_cond_signal(&cond);

				g_mutex_unlock(&mutex);
			}
		break;
		default:
		LOGW("Unknown event received -> %d", event);
	}
}

void signal_handler(int signo)
{
	if (signo != SIGTERM) {
		char *sig_name = strsignal(signo);
		LOGW("unprocessed signal is received - %s", sig_name);
		return;
	}

	LOGD("SIGTERM is received");

	deinit_proto(&proto);

	free_e1_config(&cfg);

	g_mutex_clear(&mutex);

	g_cond_clear(&cond);

	exit(EXIT_SUCCESS);
}

gboolean send_pkt_sync(struct_e1_proto *proto, uint32_t seq, void *data, int size)
{
	g_mutex_lock(&mutex);

	if (send_pkt(proto, data, size) == FALSE) {
		g_mutex_unlock(&mutex);
		printf("Sending the command failed.\n");
		return FALSE;
	}

	curr_seq = seq;

	while (curr_res == RES_NONE) {
		g_cond_wait(&cond, &mutex);
	}

	gboolean res = curr_res == RES_CMD_OK ? TRUE : FALSE;

	if (curr_res == RES_SEND_FAIL) {
		printf("There is no reply from the E1 device.\n");
	}

	curr_res = RES_NONE;

	g_mutex_unlock(&mutex);

	return res;
}

gboolean configure_channel(struct_e1_proto *proto, uint8_t tract_id, struct_e1_channel *ch)
{
	struct_add_channel ch_pkt;
	ch_pkt.hdr.type = PKT_TYPE_REQUEST;
	ch_pkt.hdr.seq = get_next_seq_n(proto);
	ch_pkt.hdr.cmd_type = E1_ADD_CHANNEL;
	ch_pkt.channel = ch->id;
	ch_pkt.vid = htons(ch->vid);
	ch_pkt.tract = tract_id;
	ch_pkt.slot_begin = ch->slot_begin;
	ch_pkt.slot_end = ch->slot_end;
	ch_pkt.hdlc = ch->hdlc;

	if (send_pkt_sync(proto, ch_pkt.hdr.seq, &ch_pkt, sizeof(ch_pkt)) == FALSE) {
		LOGE("Add the channel failed");
		return FALSE;
	}

	return TRUE;
}

gboolean configure_tract(struct_e1_proto *proto, struct_e1_tract *tract)
{
	/* Set synchronization type */
	struct_set_sync sync_pkt;
	sync_pkt.hdr.type = PKT_TYPE_REQUEST;
	sync_pkt.hdr.seq = get_next_seq_n(proto);
	sync_pkt.hdr.cmd_type = E1_SET_SYNC;
	sync_pkt.tract = tract->id;
	sync_pkt.sync_type = tract->sync;

	if (send_pkt_sync(proto, sync_pkt.hdr.seq, &sync_pkt, sizeof(sync_pkt)) == FALSE) {
		LOGE("Set sync type failed");
		return FALSE;
	}

	/* Set coding type */
	struct_set_code code_pkt;
	code_pkt.hdr.type = PKT_TYPE_REQUEST;
	code_pkt.hdr.seq = get_next_seq_n(proto);
	code_pkt.hdr.cmd_type = E1_SET_CODE;
	code_pkt.tract = tract->id;
	code_pkt.code_type = tract->code;

	if (send_pkt_sync(proto, code_pkt.hdr.seq, &code_pkt, sizeof(code_pkt)) == FALSE) {
		LOGE("Set code type failed");
		return FALSE;
	}

	/* Set framing type */
	struct_set_framing frame_pkt;
	frame_pkt.hdr.type = PKT_TYPE_REQUEST;
	frame_pkt.hdr.seq = get_next_seq_n(proto);
	frame_pkt.hdr.cmd_type = E1_SET_FRAMING;
	frame_pkt.tract = tract->id;
	frame_pkt.frame_type = tract->framing;

	if (send_pkt_sync(proto, frame_pkt.hdr.seq, &frame_pkt, sizeof(frame_pkt)) == FALSE) {
		LOGE("Set framing type failed");
		return FALSE;
	}

	int i;
	for (i = 0; i < tract->ch_num; i++) {
		if (configure_channel(proto, tract->id, &tract->channels[i]) == FALSE) {
			return FALSE;
		}
	}

	struct_req_notify notify;
	notify.hdr.type = PKT_TYPE_REQUEST;
	notify.hdr.seq = get_next_seq_n(proto);
	notify.hdr.cmd_type = E1_REQ_NOTIFY;
	notify.tract = tract->id;

	if (send_pkt_sync(proto, notify.hdr.seq, &notify, sizeof(notify)) == FALSE) {
		LOGE("Request E1 state faield");
		return FALSE;
	}

	return TRUE;
}

gboolean configure(struct_e1_proto *proto, struct_e1_config *cfg)
{
	/* Reset the E1 device configuration */
	struct_reset reset;
	reset.hdr.type = PKT_TYPE_REQUEST;
	reset.hdr.seq = get_next_seq_n(proto);
	reset.hdr.cmd_type = E1_RESET;
	if (send_pkt_sync(proto, reset.hdr.seq, &reset, sizeof(reset)) == FALSE) {
		LOGE("Sending reset command (0x%.2x) failed", E1_RESET);
		return FALSE;
	}

	int i;
	for(i = 0; i < cfg->tr_num; i++) {
		if (configure_tract(proto, &cfg->tracts[i]) == FALSE) {
			return FALSE;
		} 
	}

	return TRUE;
}

void usr_signal_handler(int signo)
{
	if (signo == SIGUSR1) {
		printf("Configuration success.\n");
	} else if (signo == SIGUSR2) {
		printf("Setup configuration failed.\n");
	} else {
		LOGE("Unknown signal -> %d", signo);
	}
}

int main()
{
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigaction(SIGTERM, &sa, 0);

	struct sigaction usr_sa;
	memset(&usr_sa, 0, sizeof(usr_sa));
	sigemptyset(&usr_sa.sa_mask);
	usr_sa.sa_flags = 0;
	usr_sa.sa_handler = usr_signal_handler;
	sigaction(SIGUSR1, NULL, 0);
	sigaction(SIGUSR2, NULL, 0);

	sigset_t usr_set;
	sigemptyset(&usr_set);
	sigaddset(&usr_set, SIGUSR1);
	sigaddset(&usr_set, SIGUSR2);

	sigprocmask(SIG_BLOCK, &usr_set, NULL);

	int parent = getpid();
	int pid = fork();

	if (pid == -1) {
		printf("Error: daemonize failed.\n");
		return -1;
	} else if (!pid) {
		umask(0);
		setsid();
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
		openlog("e1ethd", LOG_CONS, LOG_DAEMON);
		syslog(LOG_INFO, "Starting e1ethd...");

		/* Initialization */
		g_mutex_init(&mutex);
		g_cond_init(&cond);

		if (read_config(&cfg, CONF_PATH) == FALSE) {
			LOGE("Failed reading config file -> %s", CONF_PATH);
			kill(parent, SIGUSR2);
			exit(1);
		}

		if (init_proto(&proto, &cfg) == FALSE) {
			LOGE("Init failed!");
			kill(parent, SIGUSR2);
			exit(1);
		}

		register_callback(&proto, callback);

		if (configure(&proto, &cfg) == FALSE) {
			kill(parent, SIGUSR2);
			exit(1);
		} else {
			kill(parent, SIGUSR1);
		}

		while (1) {

		}
	} else {
		int sig;
		sigwait(&usr_set, &sig);

		if (sig == SIGUSR1) {
			printf("Configuration success.\n");
			return 0;
		} else if (sig == SIGUSR2) {
			printf("Setup configuration failed.\n");
			return -2;
		}

		LOGE("Unknown signal -> %d", sig);
		return -3;
	}

	return 0;
}
