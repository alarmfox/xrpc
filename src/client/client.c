#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "xrpc/debug.h"
#include "xrpc/error.h"
#include "xrpc/xrpc.h"

static struct xrpc_client *g_client = NULL;
static volatile int g_running = 1;

#define XRPC_CLIENT_VERSION "v0.0"
#define MAX_ARGS 24
#define MAX_COMMAND_SIZE 1024

struct command {
  char *name;
  char *description;
  char *usage;
  int (*handler)(int argc, char *argv[]);
};

static const char *g_client_status_str[] = {
    [XRPC_CLIENT_CONNECTED] = "connected",
    [XRPC_CLIENT_DISCONNECTED] = "disconnected",
    [XRPC_CLIENT_ERROR] = "error",
};

/*
 * Commands and handlers declaration
 */
static int cmd_help(int argc, char **argv);
static int cmd_quit(int argc, char **argv);
static int cmd_version(int argc, char **argv);
static const struct command commands[] = {
    {"help", "Show the help menu. Use help [cmd] name for specific commands",
     "help [cmd]", cmd_help},
    {"quit", "Closes the application", "quit", cmd_quit},
    {"version", "Prints the client version", "version", cmd_version},
    {NULL, NULL, NULL, 0}, // sentinel

};
/*
 * =======================================================================
 * Utility Functions
 * =======================================================================
 */
// Signal handler for graceful shutdown
static void signal_handler(int sig) {
  (void)sig;
  __atomic_store_n(&g_running, 0, __ATOMIC_SEQ_CST);
}

// Create prompt with client status
static void make_prompt(char *buf, size_t len) {
  enum xrpc_client_status status = xrpc_client_status_get(g_client);
  const char *status_str =
      (status < 3) ? g_client_status_str[status] : "unknown";
  snprintf(buf, len, "xrpc-cli [%s] > ", status_str);
}

static const struct command *get_command_by_name(const char *name) {
  for (const struct command *cmd = commands; cmd->name; cmd++) {
    if (!strcmp(name, cmd->name)) return cmd;
  }

  return NULL;
}

/*
 * Execute command
 */

static void execute_command(char *line) {
  if (!line) return;
  const struct command *cmd = NULL;
  // parse command: first string is the cmd name, other are treated as
  // parameters
  int argc = 0;
  char *argv[MAX_ARGS];
  memset(argv, 0, sizeof(argv));

  for (char *p = strtok(line, " \t"); p != NULL; p = strtok(NULL, " \t")) {
    argv[argc++] = p;
  }

  if (argc == 0) return;

  cmd = get_command_by_name(line);

  if (!cmd) {
    printf("Unrecognized command: %s\n", line);
    cmd_help(0, 0);
    return;
  }

  if (cmd->handler) cmd->handler(argc, argv);
}

static void interactive_loop() {
  char buf[MAX_COMMAND_SIZE];
  char pref[256] = {0};

  make_prompt(pref, 256);

  printf("%s", pref);
  fflush(stdout);
  while (__atomic_load_n(&g_running, __ATOMIC_RELAXED) &&
         fgets(buf, MAX_COMMAND_SIZE, stdin) != NULL) {

    // trim leading spaces string
    char *start = buf;
    while (isspace(*start))
      start++;

    if (*start == 0) goto next;

    // trim terminating spaces
    char *end = buf + strlen(buf) - 1;
    while (end > start && isspace(*end))
      end--;
    end[1] = '\0';

    if (0 == end - start) goto next;

    execute_command(start);

  next:
    memset(buf, 0, MAX_COMMAND_SIZE);
    memset(pref, 0, 256);
    make_prompt(pref, 256);

    printf("%s", pref);
    fflush(stdout);
  }
}

/*
 * Handlers
 */
static int cmd_help(int argc, char **argv) {
  (void)argv;

  printf("XRPC Client " XRPC_CLIENT_VERSION "\n\n");

  if (argc > 1) {
    printf("Usage: help [cmd]\n");
    return 1;
  }

  if (argc == 1) {
    const struct command *cmd = get_command_by_name(argv[0]);
    if (!cmd) {
      printf("Unrecognized command: %s\n", argv[0]);
    } else {
      printf("%s: %s\n%s", cmd->name, cmd->description, cmd->usage);
    }
  }

  // Print the list of commands
  if (argc == 0) {
    printf("Available commands:\n");
    for (const struct command *cmd = commands; cmd->name; cmd++) {
      printf("  %-10s %s\n", cmd->name, cmd->description);
    }
    return 0;
  }

  return 0;
}

static int cmd_quit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  __atomic_store_n(&g_running, 0, __ATOMIC_SEQ_CST);

  return XRPC_SUCCESS;
}

static int cmd_version(int argc, char **argv) {
  (void)argc;
  (void)argv;

  printf(XRPC_CLIENT_VERSION "\n");

  return XRPC_SUCCESS;
}

int main(void) {
  int ret;

  // Set up signal handling
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  printf("XRPC Client " XRPC_CLIENT_VERSION "\n");

  if (ret = xrpc_client_init(&g_client), ret != XRPC_SUCCESS) {
    printf("Error: failed to initialize client: %d\n", ret);
    return 1;
  }

  interactive_loop();

  if (g_client) {
    if (xrpc_client_is_connected(g_client)) {
      printf("Disconnecting from server... \n");
      xrpc_client_disconnect(g_client);
    }
    xrpc_client_free(g_client);
  }
}
