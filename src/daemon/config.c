#include <stdlib.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <syslog.h>

#include "config.h"
#include "debug.h"
#include "commands.h"

gboolean read_config(struct_e1_config *config, char *config_file)
{
	gboolean ret = TRUE;

	config->tracts = NULL;
	config->src_addr = NULL;
	config->dst_addr = NULL;
	config->tracts = NULL;

	GKeyFile *key_file = NULL;
	GError *error = NULL;

	key_file = g_key_file_new();

	if (!g_key_file_load_from_file(key_file, config_file, G_KEY_FILE_NONE, &error)) {
		LOGE("Parse %s failed: %s", config_file, error->message);
		g_key_file_free(key_file);
		ret = FALSE;
		goto exit;
	}

	/* Read UDP port value */
	config->udp_port = g_key_file_get_integer(key_file, GRP_MAIN, KEY_UDP_PORT, &error);
	if (error != NULL) {
		config->udp_port = DEFAULT_UDP_PORT;
		LOGW("UDP port is set to default value: %d", DEFAULT_UDP_PORT);
		g_clear_error(&error);
	}

	/* Read source address */
	config->src_addr = g_key_file_get_string(key_file, GRP_MAIN, KEY_SRC_ADDR, &error);
	if (error != NULL) {
		LOGW("Reading of the source address failed. Set default -> %s", DEFAULT_SRC_ADDR);
		g_clear_error(&error);
		config->src_addr = g_strdup(DEFAULT_SRC_ADDR);
	}

	/* Read destination address */
	config->dst_addr = g_key_file_get_string(key_file, GRP_MAIN, KEY_DST_ADDR, &error);
	if (error != NULL) {
		LOGW("Reading of the destintaion address failed. Set default -> %s", DEFAULT_DST_ADDR);
		g_clear_error(&error);
		config->dst_addr = g_strdup(DEFAULT_DST_ADDR);
	}

	/* Read tracts configuration */
	gint *tracts = g_key_file_get_integer_list(key_file, GRP_MAIN, KEY_TRACTS, &config->tr_num, &error);
	if (tracts == NULL) {
		LOGE("Reading list of tracts failed: %s", error->message);
		g_clear_error(&error);
		ret = FALSE;
		goto exit;
	}

	config->tracts = (struct_e1_tract*)malloc(config->tr_num * sizeof(struct_e1_tract));

	int i;
	for (i = 0; i < config->tr_num; i++) {
		if (!parse_tract(key_file, tracts[i], error, &config->tracts[i])) {
			LOGE("Parsing tract config (id = %d) faield", tracts[i]);
			g_free(tracts);
			ret = FALSE;
			goto exit;
		}
	}


	g_free(tracts);

exit:
	if (key_file != NULL) g_key_file_free(key_file);
	if (ret == FALSE) free_e1_config(config);
	return ret;
}

static gboolean parse_tract(GKeyFile *key_file, gint tract_id, GError *err, struct_e1_tract *tract)
{
	tract->channels = NULL;

	tract->id = tract_id;

	char grp_str[GRP_DIGIT];
	gint buf_len;
	g_ascii_dtostr(grp_str, GRP_DIGIT, tract_id);

	char *sync = g_key_file_get_string(key_file, grp_str, KEY_SYNC, &err);
	if (sync == NULL) {
		LOGE("Getting the sync type failed: %s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	if (!g_strcmp0(CFG_SYNC_INNER, sync)) {
		tract->sync = SYNC_INNER;
	} else if (!g_strcmp0(CFG_SYNC_OUTER, sync)) {
		tract->sync = SYNC_OUTER;
	} else {
		LOGE("Unsupportable synchronization type - %s", sync);
		g_free(sync);
		return FALSE;
	}

	g_free(sync);

	char *code = g_key_file_get_string(key_file, grp_str, KEY_CODE, &err);
	if (code == NULL) {
		LOGE("Getting the coding type failed: %s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	if (!g_strcmp0(CFG_CODE_HDB3, code)) {
		tract->code = CODE_HDB3;
	} else if (!g_strcmp0(CFG_CODE_AMI, code)) {
		tract->code = CODE_AMI;
	} else {
		LOGE("Unsupportable coding type - %s", code);
		g_free(code);
		return FALSE;
	}

	g_free(code);

	char *framing = g_key_file_get_string(key_file, grp_str, KEY_FRAMING, &err);
	if (framing == NULL) {
		LOGE("Getting the framing type failed: %s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	if (!g_strcmp0(CFG_FRAME_G704, framing)) {
		tract->framing = FRAME_G704;
	} else if (!g_strcmp0(CFG_FRAME_G704_NO_SRC, framing)) {
		tract->framing = FRAME_G704_NO_SRC;
	} else if (!g_strcmp0(CFG_FRAME_UNFRAMED, framing)) {
		tract->framing = FRAME_UNFRAMED;
	} else {
		LOGE("Unsupportable framing type - %s", framing);
		g_free(framing);
		return FALSE;
	}

	g_free(framing);

	gint *ch_ids = g_key_file_get_integer_list(key_file, grp_str, KEY_CHANNELS, &tract->ch_num, &err);
	if (ch_ids == NULL) {
		LOGE("Getting the channels failed: %s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	tract->channels = (struct_e1_channel*)malloc(tract->ch_num * sizeof(struct_e1_channel));

	int i;
	for(i = 0; i < tract->ch_num; i++) {
		if (!parse_channel(key_file, grp_str, ch_ids[i], err, &tract->channels[i])) {
			LOGE("Parsing channel config (id = %d) failed", ch_ids[i]);
			g_free(ch_ids);
			return FALSE;
		}
	}

	g_free(ch_ids);

	return TRUE;
}

static gboolean parse_channel(GKeyFile *key_file, gchar *tract_str, gint ch_id, GError *err, struct_e1_channel *channel)
{
	gboolean ret = TRUE;
	channel->id = ch_id;

	char ch_str[GRP_DIGIT];
	gint buf_len;

	g_ascii_dtostr(ch_str, GRP_DIGIT, ch_id);

	char *grp_str = g_strconcat(tract_str, GRP_SEPARATOR, &ch_str, NULL);

	char *hdlc = g_key_file_get_string(key_file, grp_str, KEY_HDLC, &err);
	if (hdlc == NULL) {
		LOGE("Getting the hdlc type failed: %s", err->message);
		g_clear_error(&err);
		ret = FALSE;
		goto exit;
	}

	if (!g_strcmp0(CFG_HDLC_ETH, hdlc)) {
		channel->hdlc = HDLC_ETH;
	} else if (!g_strcmp0(CFG_HDLC_IP, hdlc)) {
		channel->hdlc = HDLC_IP;
	} else {
		LOGE("Unsupportable HDLC type - %s", hdlc);
		g_free(hdlc);
		return FALSE;
	}

	g_free(hdlc);

	channel->vid = g_key_file_get_integer(key_file, grp_str, KEY_VID, &err);
	if (err != NULL) {
		LOGE("Getting a channel VID failed");
		g_clear_error(&err);
		ret = FALSE;
		goto exit;
	}

	channel->slot_begin = g_key_file_get_integer(key_file, grp_str, KEY_SLOT_BEGIN, &err);
	if (err != NULL) {
		LOGE("Getting a channel slots begin value failed");
		g_clear_error(&err);
		ret = FALSE;
		goto exit;
	}

	channel->slot_end = g_key_file_get_integer(key_file, grp_str, KEY_SLOT_END, &err);
	if (err != NULL) {
		LOGE("Getting a channel slots end value failed");
		g_clear_error(&err);
		ret = FALSE;
		goto exit;
	}

exit:
	g_free(grp_str);
	return ret;
}

void free_e1_config(struct_e1_config *cfg)
{
	LOGD(">>>");

	if (cfg == NULL) return;

	if(cfg->src_addr != NULL) g_free(cfg->src_addr);
	if(cfg->dst_addr != NULL) g_free(cfg->dst_addr);


	if (cfg->tracts == NULL) return;

	int i;
	for (i = 0; i < cfg->tr_num; i++) {
		free_e1_tract(&cfg->tracts[i]);
	}

	free(cfg->tracts);

	LOGD("<<<");
}

static void free_e1_tract(struct_e1_tract *tract)
{
	if (tract == NULL) return;

	if (tract->channels == NULL) return;

	free(tract->channels);
}
