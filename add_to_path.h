#ifndef ADD_TO_PATH_H
#define ADD_TO_PATH_H

#ifdef _WIN32
    #include <windows.h>
    #include <shlobj.h>
#else
    #include <unistd.h>
    #include <pwd.h>
    #include <sys/stat.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int is_in_path(const char *program_name);
int add_to_system_path(const char *executable_path);
int setup_path_integration(void);

#endif