#ifndef CONFIG_H_
#define CONFIG_H_ 1

#include <glib.h>

#define CONF_PATH "/etc/e1ethd.conf"
#define G_NAME "e1ethd"
#define DEFAULT_UDP_PORT 28960

typedef struct E1Config {
	gchar *src_addr;
	gchar *dst_addr;
	int udp_port;
} E1Config;

gboolean read_config(E1Config *config, char *config_file);

#endif // CONFIG_H_
