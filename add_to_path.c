#include "add_to_path.h"

int is_in_path(const char *program_name) {
    char command[512];
    
#ifdef _WIN32
    snprintf(command, sizeof(command), "where %s >nul 2>&1", program_name);
#else
    snprintf(command, sizeof(command), "which %s >/dev/null 2>&1", program_name);
#endif
    
    return system(command) == 0;
}

#ifdef _WIN32
int add_to_system_path(const char *executable_path) {
    HKEY hKey;
    char current_path[32768];
    DWORD path_size = sizeof(current_path);
    char new_path[32768];
    char dir_path[512];
    
    strcpy(dir_path, executable_path);
    char *last_slash = strrchr(dir_path, '\\');
    if (last_slash) *last_slash = '\0';
    
    if (RegOpenKeyEx(HKEY_CURRENT_USER, 
                     "Environment", 
                     0, 
                     KEY_READ | KEY_WRITE, 
                     &hKey) != ERROR_SUCCESS) {
        return 0;
    }
    
    if (RegQueryValueEx(hKey, "PATH", NULL, NULL, 
                        (BYTE*)current_path, &path_size) != ERROR_SUCCESS) {
        current_path[0] = '\0';
    }
    
    if (strstr(current_path, dir_path) != NULL) {
        RegCloseKey(hKey);
        return 1;
    }
    
    if (strlen(current_path) > 0) {
        snprintf(new_path, sizeof(new_path), "%s;%s", current_path, dir_path);
    } else {
        strcpy(new_path, dir_path);
    }
    
    if (RegSetValueEx(hKey, "PATH", 0, REG_EXPAND_SZ, 
                      (BYTE*)new_path, strlen(new_path) + 1) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 0;
    }
    
    RegCloseKey(hKey);
    
    SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 
                       (LPARAM)"Environment", SMTO_ABORTIFHUNG, 5000, NULL);
    
    return 1;
}
#else
int add_to_system_path(const char *executable_path) {
    char dir_path[512];
    char bashrc_path[512];
    char profile_path[512];
    FILE *file;
    struct passwd *pw = getpwuid(getuid());
    
    if (!pw) return 0;
    
    strcpy(dir_path, executable_path);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) *last_slash = '\0';
    
    snprintf(bashrc_path, sizeof(bashrc_path), "%s/.bashrc", pw->pw_dir);
    snprintf(profile_path, sizeof(profile_path), "%s/.profile", pw->pw_dir);
    
    char export_line[1024];
    snprintf(export_line, sizeof(export_line), "export PATH=\"$PATH:%s\"\n", dir_path);
    
    file = fopen(bashrc_path, "a");
    if (file) {
        fprintf(file, "\n# Added by iScanner\n%s", export_line);
        fclose(file);
    }
    
    file = fopen(profile_path, "a");
    if (file) {
        fprintf(file, "\n# Added by iScanner\n%s", export_line);
        fclose(file);
    }
    
    char bin_dir[512];
    snprintf(bin_dir, sizeof(bin_dir), "%s/bin", pw->pw_dir);
    mkdir(bin_dir, 0755);
    
    char symlink_path[512];
    snprintf(symlink_path, sizeof(symlink_path), "%s/bin/iscanner", pw->pw_dir);
    
    unlink(symlink_path);
    if (symlink(executable_path, symlink_path) == 0) {
        chmod(symlink_path, 0755);
        return 1;
    }
    
    return 0;
}
#endif

int setup_path_integration(void) {
    char executable_path[1024];
    
#ifdef _WIN32
    if (GetModuleFileName(NULL, executable_path, sizeof(executable_path)) == 0) {
        return 0;
    }
#else
    ssize_t len = readlink("/proc/self/exe", executable_path, sizeof(executable_path) - 1);
    if (len == -1) return 0;
    executable_path[len] = '\0';
#endif
    
    return add_to_system_path(executable_path);
}