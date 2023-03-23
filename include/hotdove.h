#ifndef HOTDOVE_H
#define HOTDOVE_H

#include <stddef.h>
#include <stdbool.h>

#ifndef MAX_MESSAGE_LENGTH
#define MAX_MESSAGE_LENGTH 4096
#endif

// Numbers must be sorted
#define HOTDOVE_PARAM_DEV \
  X( 0, DEVPATH) \
  X( 1, ACTION) \
  X( 2, SERVICE) \
  X( 3, SYSTEMD_WANTS) \
  X( 4, SYSTEMD_USER_WANTS) \
  X( 5, SYSTEMD_READY)

enum hotdove_param_dev_e {
#define X(I,Y) HOTDOVE_PARAM_DEV_ ## Y,
  HOTDOVE_PARAM_DEV
#undef X
  HOTDOVE_PARAM_DEV_COUNT
};

extern const char*const hotdove_param_dev_s[HOTDOVE_PARAM_DEV_COUNT];
extern const char hotdove_service_user[];

struct hotdove_dev_meta {
  const char* p[HOTDOVE_PARAM_DEV_COUNT];
};

int hotdove_connect(void); // This function is idempotent, so long hotdove_cleanup isn't called. It's also called by the other functions.
bool hotdove_status(void);
bool hotdove_stop(bool zap);
bool hotdove_auth(void);
bool hotdove_dev(const struct hotdove_dev_meta*const dm);
void hotdove_cleanup(void); // This also closes current connections

// Internal functions
bool hotdove__send(size_t length, const char message[restrict length], bool try_authenticate);
void hotdove__set_server_fd(int fd);


#endif
