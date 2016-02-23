#include <stdlib.h>
#include <syslog.h>
#include <glib.h>
#include <gio/gio.h>
#include <netinet/in.h>

#include "config.h"
#include "protocol.h"

int main() {
	E1Proto proto;
	E1Config cfg;

	openlog("e1ethd", LOG_CONS, LOG_DAEMON);
	syslog(LOG_INFO, "Starting e1ethd");
	if (read_config(&cfg, CONF_PATH) == FALSE) {
		syslog(LOG_ERR, "Failed reading config file -> %s", CONF_PATH);
		return -1;
	}

	/*** Initialization ***/
	if (init_proto(&proto, &cfg) == FALSE) {
		syslog(LOG_ERR, "Init failed!");
		return -2;
	}

	/*** Send msg ***/
	test_send_pkt(&proto);

	/*** Create and Start loop for receive msg from board ***/

	deinit_proto(&proto);
	return 0;
}
