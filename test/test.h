#ifndef XRPC_TEST_H
#define XRPC_TEST_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test statistics
struct xrpc_test_statistics {
  int total_tests;
  int passed_tests;
  int failed_tests;
  const char *current_suite;
};

static struct xrpc_test_statistics stats = {0, 0, 0, ""};

// Color codes for output
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_RESET "\x1b[0m"

// Test macros
#define TEST_SUITE(name)                                                       \
  do {                                                                         \
    stats.current_suite = name;                                                \
    printf(COLOR_BLUE "=== Running %s ===" COLOR_RESET "\n", name);            \
  } while (0)

#define TEST_CASE(name)                                                        \
  do {                                                                         \
    printf("  Running: %s... ", name);                                         \
    fflush(stdout);                                                            \
    stats.total_tests++;                                                       \
  } while (0)

#define TEST_ASSERT(condition, message)                                        \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf(COLOR_RED "FAIL" COLOR_RESET "\n");                               \
      printf("    Assertion failed: %s\n", message);                           \
      printf("    File: %s:%d\n", __FILE__, __LINE__);                         \
      stats.failed_tests++;                                                    \
      return -1;                                                               \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_EQ(expected, actual, message)                              \
  do {                                                                         \
    if ((expected) != (actual)) {                                              \
      printf(COLOR_RED "FAIL" COLOR_RESET "\n");                               \
      printf("    %s\n", message);                                             \
      printf("    Expected: %ld, Got: %ld\n", (long)(expected),                \
             (long)(actual));                                                  \
      printf("    File: %s:%d\n", __FILE__, __LINE__);                         \
      stats.failed_tests++;                                                    \
      return -1;                                                               \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_PTR_EQ(expected, actual, message)                          \
  do {                                                                         \
    if ((expected) != (actual)) {                                              \
      printf(COLOR_RED "FAIL" COLOR_RESET "\n");                               \
      printf("    %s\n", message);                                             \
      printf("    Expected: %p, Got: %p\n", (void *)(expected),                \
             (void *)(actual));                                                \
      printf("    File: %s:%d\n", __FILE__, __LINE__);                         \
      stats.failed_tests++;                                                    \
      return -1;                                                               \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_NULL(ptr, message) TEST_ASSERT_PTR_EQ(NULL, ptr, message)

#define TEST_ASSERT_NOT_NULL(ptr, message) TEST_ASSERT((ptr) != NULL, message)

#define TEST_SUCCESS()                                                         \
  do {                                                                         \
    printf(COLOR_GREEN "PASS" COLOR_RESET "\n");                               \
    stats.passed_tests++;                                                      \
    return 0;                                                                  \
  } while (0)

#define TEST_FAIL(message)                                                     \
  do {                                                                         \
    printf(COLOR_RED "FAIL" COLOR_RESET "\n");                                 \
    printf("    %s\n", message);                                               \
    printf("    File: %s:%d\n", __FILE__, __LINE__);                           \
    stats.failed_tests++;                                                      \
    return -1;                                                                 \
  } while (0)

// Test runner macros
#define RUN_TEST(test_func)                                                    \
  do {                                                                         \
    if (test_func() != 0) { /* Test already reported failure */                \
    }                                                                          \
  } while (0)

#define TEST_REPORT()                                                          \
  do {                                                                         \
    printf("\n" COLOR_BLUE "=== Test Summary ===" COLOR_RESET "\n");           \
    printf("Total tests: %d\n", stats.total_tests);                            \
    printf(COLOR_GREEN "Passed: %d" COLOR_RESET "\n", stats.passed_tests);     \
    if (stats.failed_tests > 0) {                                              \
      printf(COLOR_RED "Failed: %d" COLOR_RESET "\n", stats.failed_tests);     \
    } else {                                                                   \
      printf("Failed: 0\n");                                                   \
    }                                                                          \
    printf("\n");                                                              \
    if (stats.failed_tests == 0) {                                             \
      printf(COLOR_GREEN "All tests passed!" COLOR_RESET "\n");                \
      exit(0);                                                                 \
    } else {                                                                   \
      printf(COLOR_RED "Some tests failed!" COLOR_RESET "\n");                 \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#endif // !XRPC_TEST_H
