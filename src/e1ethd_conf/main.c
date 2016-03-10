#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <string.h>
#include <stdint.h>

void usage(char *exe)
{
	printf("usage: %s file group key value\n", exe);
}

void clear_file(char *file_name)
{
	const char *cmd = "echo \"\" > ";

	uint8_t len = strlen(cmd) + strlen(file_name);

	char *full_cmd = (char*)malloc(sizeof(char) * len);

	sprintf(full_cmd, "%s%s", cmd, file_name);
	system(full_cmd);

	free(full_cmd);
}

int main(int argc, char *argv[])
{
	if (argc < 5) {
		usage(argv[0]);
		return -1;
	}

	int ret = 0;

	char *cfg_file = argv[1];
	char *group = argv[2];
	char *key = argv[3];

	GKeyFile *key_file = g_key_file_new();
	GError *error = NULL;

	if (g_key_file_load_from_file(key_file, cfg_file, G_KEY_FILE_NONE, &error) != TRUE) {
		printf("Parse %s failed: %s", cfg_file, error->message);
		g_key_file_free(key_file);
		g_clear_error(&error);
		return -1;
	}

	if (argc > 5) {
		uint8_t len = argc - 4;
		gint *list = (gint*)malloc(sizeof(gint) * len);

		int i;
		for (i = 4; i < argc; i++) {
			list[i-4] = atoi(argv[i]);
		}

		g_key_file_set_integer_list(key_file, group, key, list, len);

		free(list);
	} else {
		g_key_file_set_value(key_file, group, key, argv[4]);
	}

	gsize length;
	gchar *data = g_key_file_to_data(key_file, &length, &error);
	if (g_file_set_contents(cfg_file, data, length, &error) != TRUE) {
		printf("Writing configuration to the file %s was failed: %s\n", cfg_file, error->message);
		ret = -1;
		goto exit;
	}

exit:
	g_free(data);
	g_clear_error(&error);
	g_key_file_free(key_file);

	return ret;
}