#include <glib.h>
#include <syslog.h>

#include "config.h"

gboolean read_config(E1Config *config, char *config_file) {
	GKeyFile* key_file;
	GError *error = NULL;

	key_file = g_key_file_new();

	if (g_key_file_load_from_file(key_file, config_file, G_KEY_FILE_NONE, &error) != TRUE) {
		syslog(LOG_ERR, "Parse %s failed: %s", config_file, error->message);
		g_key_file_free(key_file);
		return FALSE;
	}

	/*** Read UDP port value ***/
	config->udp_port = g_key_file_get_integer(key_file, G_NAME, "UDPPort", &error);
	if (error != NULL) {
		config->udp_port = DEFAULT_UDP_PORT;
		syslog(LOG_WARNING, "UDP port is set to default value: %d", DEFAULT_UDP_PORT);
		g_error_free(error);
	}

	/*** Read source address ***/
	config->src_addr = g_key_file_get_string(key_file, G_NAME, "UDPSrcAddr", &error);
	if (error != NULL) {
		syslog(LOG_ERR, "Failed reading source address");
		g_error_free(error);
		return FALSE;
	}

	/*** Read destination address ***/
	config->dst_addr = g_key_file_get_string(key_file, G_NAME, "UDPDstAddr", &error);
	if (error != NULL) {
		syslog(LOG_ERR, "Failed reading destination address");
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}
