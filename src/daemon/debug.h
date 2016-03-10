#ifndef DEBUG_H_
#define DEBUG_H_ 1

#include <syslog.h>

#define LOGD(fmt, ...) syslog(LOG_DEBUG, "%s() : " fmt, __func__, ##__VA_ARGS__)
#define LOGE(fmt, ...) syslog(LOG_ERR, "%s() : " fmt, __func__, ##__VA_ARGS__)
#define LOGW(fmt, ...) syslog(LOG_WARNING, "%s() : " fmt, __func__, ##__VA_ARGS__)

#endif /* DEBUG_H_ */
