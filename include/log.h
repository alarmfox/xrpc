#ifndef __LOG_H
#define __LOG_H

enum LOG_LEVEL {
  LOG_LV_DEBUG = 0,
  LOG_LV_INFO = 1,
  LOG_LV_WARN = 2,
  LOG_LV_ERROR = 3
};

#define BLUE                                                                   \
  "\x05"                                                                       \
  "DEBUG\033[34m"
#define GREEN                                                                  \
  "\x04"                                                                       \
  "INFO\033[32m"
#define YELLOW                                                                 \
  "\x04"                                                                       \
  "WARN\033[33m"
#define RED                                                                    \
  "\x05"                                                                       \
  "ERROR\033[31m"
#define RESET "\033[0m"

void log_init(const char *p);
void log_message(enum LOG_LEVEL level, const char *msg);
void log_set_minimum_level(enum LOG_LEVEL level);
void log_free();

static inline char *__color_by_level(const enum LOG_LEVEL l) {
  switch (l) {
  case LOG_LV_INFO:
    return GREEN;
    break;
  case LOG_LV_WARN:
    return YELLOW;
    break;
  case LOG_LV_ERROR:
    return RED;
    break;
  default:
    return BLUE;
  };
}

#endif // !__LOG_H
