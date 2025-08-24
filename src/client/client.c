#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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
  void (*handler)(int argc, char *argv[]);
};

static const char *g_client_status_str[] = {
    [XRPC_CLIENT_CONNECTED] = "connected ",
    [XRPC_CLIENT_DISCONNECTED] = "disconnected",
    [XRPC_CLIENT_ERROR] = "error",
};

/*
 * Commands and handlers declaration
 */
static void cmd_connect(int argc, char **argv);
static void cmd_disconnect(int argc, char **argv);
static void cmd_help(int argc, char **argv);
static void cmd_quit(int argc, char **argv);
static void cmd_version(int argc, char **argv);
static const struct command commands[] = {
    {
        "help",
        "Show the help menu",
        "help [cmd]\ncmd: command to get information about",
        cmd_help,
    },
    {"connect", "Connects to a server",
     "connect <proto>://<server>:<port> [...args]", cmd_connect},
    {"disconnect", "Disconnect from a currently connected server", "disconnect",
     cmd_disconnect},
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
  snprintf(buf, len, "xrpc-cli [%s%s] > ", status_str,
           xrpc_client_get_server_name(g_client));
}

static const struct command *get_command_by_name(const char *name) {
  for (const struct command *cmd = commands; cmd->name; cmd++) {
    if (!strcmp(name, cmd->name)) return cmd;
  }

  return NULL;
}

// Print error message with error code
static void print_error(const char *operation, int error_code) {
  printf("Error: %s failed with code %d\n", operation, error_code);

  // Add specific error messages for common codes
  switch (error_code) {
  case XRPC_CLIENT_ERR_NOT_CONNECTED:
    printf("  Client is not connected to server\n");
    break;
  case XRPC_CLIENT_ERR_INVALID_CONFIG:
    printf("  Invalid configuration provided\n");
    break;
  case XRPC_CLIENT_ERR_CONNECT:
    printf("  Failed to connect to server\n");
    break;
  case XRPC_TRANSPORT_ERR_CONN_CLOSED:
    printf("  Connection was closed by server\n");
    break;
  case XRPC_INTERNAL_ERR_ALLOC:
    printf("  Memory allocation failed\n");
    break;
  case XRPC_CLIENT_ERR_NOT_IMPLEMENTED:
    printf("  Not yet implemented\n");
  }
}

// Parse address string like "tcp://127.0.0.1:9000"
static int make_config_from_address(const char *addr_str,
                                    struct xrpc_client_config *cfg) {
  if (!addr_str || !cfg) { return XRPC_CLIENT_ERR_INVALID_CONFIG; }

  // Simple parsing for TCP addresses
  if (strncmp(addr_str, "tcp://", 6) != 0) {
    printf("Error: Only TCP addresses supported (format: tcp://host:port)\n");
    return XRPC_CLIENT_ERR_INVALID_CONFIG;
  }

  const char *hostport = addr_str + 6; // Skip "tcp://"
  char *colon = strrchr(hostport, ':');
  if (!colon) {
    printf("Error: Port not specified in address\n");
    return XRPC_CLIENT_ERR_INVALID_CONFIG;
  }

  // Extract host and port
  size_t host_len = colon - hostport;
  char host[256] = {0};
  if (host_len >= sizeof(host)) {
    printf("Error: Hostname too long\n");
    return XRPC_CLIENT_ERR_INVALID_CONFIG;
  }

  strncpy(host, hostport, host_len);
  int port = atoi(colon + 1);

  if (port <= 0 || port > 65535) {
    printf("Error: Invalid port number: %d\n", port);
    return XRPC_CLIENT_ERR_INVALID_CONFIG;
  }

  // Convert hostname to IP (simple case - just handle localhost and IP
  // addresses)
  struct in_addr addr;
  if (strcmp(host, "localhost") == 0 || strcmp(host, "127.0.0.1") == 0) {
    addr.s_addr = htonl(INADDR_LOOPBACK);
  } else if (inet_aton(host, &addr) == 0) {
    printf("Error: Invalid or unsupported hostname: %s\n", host);
    printf("Hint: Use IP addresses or 'localhost'\n");
    return XRPC_CLIENT_ERR_INVALID_CONFIG;
  }

  // Set up configuration
  *cfg =
      (struct xrpc_client_config){.type = XRPC_TRANSPORT_TCP,
                                  .config.tcp = {
                                      .addr =
                                          {
                                              .sin_family = AF_INET,
                                              .sin_port = htons((uint16_t)port),
                                              .sin_addr = addr,
                                          },
                                      .nodelay = true,
                                      .keepalive = false,
                                      .connect_timeout_ms = 5000,
                                      .send_timeout_ms = 1000,
                                      .recv_timeout_ms = 1000,
                                      .send_buffer_size = -1,
                                      .recv_buffer_size = -1,
                                  }};

  return XRPC_SUCCESS;
}

/*
 * Execute command
 */

static void execute_command(const char *input) {
  if (!input || strlen(input) == 0) return;

  const struct command *cmd = NULL;
  // parse command: first string is the cmd name, other are treated as
  // parameters
  int argc = 0;
  char *argv[MAX_ARGS];
  char *arg = malloc(strlen(input));

  memset(argv, 0, sizeof(argv));
  memcpy(arg, input, strlen(input));

  for (char *p = strtok(arg, " \t"); p != NULL && argc < MAX_ARGS;
       p = strtok(NULL, " \t")) {
    argv[argc++] = p;
  }

  if (argc == 0) return;

  cmd = get_command_by_name(argv[0]);

  if (!cmd) {
    printf("Unknown command: %s\n", argv[0]);
    printf("Type 'help' for available commands or 'help <cmd>'to know more "
           "about specific commands.\n");
    return;
  }

  if (cmd->handler) {
    // skip the first argument since it is the command name
    cmd->handler(argc - 1, argv + 1);
  }

  if (arg) free(arg);
}

/*
 * Handlers
 */
static void cmd_help(int argc, char **argv) {
  printf("XRPC Client " XRPC_CLIENT_VERSION "\n\n");

  /*
   * If there is a command specified as parameter print out the description  and
   * usage. Otherwise print the list of available commands
   */
  if (argc == 1) {
    const struct command *cmd = get_command_by_name(argv[0]);
    if (!cmd) {
      printf("Unrecognized command: %s\n", argv[0]);
    } else {
      printf("%s: %s\nUsage: %s\n", cmd->name, cmd->description, cmd->usage);
    }
  } else {
    printf("Available commands:\n");
    for (const struct command *cmd = commands; cmd->name; cmd++) {
      printf("  %-10s %s\n", cmd->name, cmd->description);
    }
  }
}

/*
 * Connects to a server. The server address must be specified as:
 * <proto>://<address>:<port>. The user can pass parameters to configure the
 * connection. Right now only tcp protocol is supported
 */
static void cmd_connect(int argc, char **argv) {
  if (argc < 1) {
    printf("Error: connect missing server address\n");
    return;
  }

  int ret;
  struct xrpc_client_config cfg = {0};

  if (make_config_from_address(argv[0], &cfg) != XRPC_SUCCESS) return;

  if (ret = xrpc_client_connect(g_client, &cfg), ret != XRPC_SUCCESS) {
    print_error("connect", ret);
    return;
  }
}

static void cmd_disconnect(int argc, char **argv) {
  (void)argc;
  (void)argv;

  int ret;

  if (ret = xrpc_client_disconnect(g_client), ret != XRPC_SUCCESS) {
    print_error("disconnect", ret);
    return;
  }
}

/*
 * Quits the application
 */
static void cmd_quit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  __atomic_store_n(&g_running, 0, __ATOMIC_SEQ_CST);
}

/*
 * Print version
 */
static void cmd_version(int argc, char **argv) {
  (void)argc;
  (void)argv;

  printf(XRPC_CLIENT_VERSION "\n");
}

/*
 * Main loop of the application.
 */
static void interactive_loop() {
  char buf[MAX_COMMAND_SIZE];
  char prompt[256] = {0};

  while (__atomic_load_n(&g_running, __ATOMIC_RELAXED)) {

    make_prompt(prompt, 256);

    printf("%s", prompt);
    fflush(stdout);

    // Read input
    if (!fgets(buf, sizeof(buf), stdin)) {
      if (feof(stdin)) {
        printf("\n");
        break;
      } else {
        printf("Error reading input\n");
        continue;
      }
    }
    // trim leading spaces string
    char *start = buf;
    while (isspace(*start))
      start++;

    if (*start == 0) continue;

    // trim terminating spaces
    char *end = buf + strlen(buf) - 1;
    while (end > start && isspace(*end))
      end--;
    end[1] = '\0';

    if (0 == (end - start)) continue;

    execute_command(start);
  }
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
