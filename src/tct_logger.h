#ifndef LOGGING_UTILS
#define LOGGING_UTILS

#include <stdio.h>

#define TCT_LOGGER_INFO(format, ...) {                              \
    fprintf(stderr, "TCT [INFO]: " format "\n", ##__VA_ARGS__);     \
}

#define TCT_LOGGER_ERROR(format, ...) {                             \
    fprintf(stderr, "TCT [ERROR]: " format "\n", ##__VA_ARGS__);    \
}

#define TCT_LOGGER_DEBUG(format, ...) {                          \
    fprintf(stderr, "TCT [DEBUG]: " format "\n", ##__VA_ARGS__); \
}

#endif