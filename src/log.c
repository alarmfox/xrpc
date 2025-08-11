#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char *prefix;
static enum LOG_LEVEL min_level = LOG_LV_INFO;

void log_init(const char *p) {
  size_t l = strlen(p);
  prefix = malloc(1 + sizeof(char) * l);
  strcpy(prefix, p);
}

void log_message(enum LOG_LEVEL level, const char *msg) {
  if (level < min_level)
    return;

  char level_name[6];
  char time_format[64];
  char *color = __color_by_level(level);
  unsigned char sz = color[0];

  strncpy(level_name, color + 1, sz);
  for (int i = sz; i < 6; ++i) {
    level_name[i] = ' ';
  }
  level_name[5] = '\0';
  color += 1 + sz;

  time_t t = time(NULL);
  struct tm *p = localtime(&t);

  strftime(time_format, sizeof(time_format), "%Y-%m-%d %H:%M:%S", p);

  printf("%s[%s][%s][%s]%s %s\n", color, level_name, time_format, prefix, RESET,
         msg);
}

void log_set_minimum_level(enum LOG_LEVEL level) { min_level = level; }

void log_free() {
  free(prefix);
  prefix = NULL;
}
