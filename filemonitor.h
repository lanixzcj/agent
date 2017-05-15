#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H
#include <queue>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <semaphore.h>
#include <time.h>
#include <pwd.h>

#include <string.h>
#include <sys/dir.h>	// readdir
#include <limits.h>	// PATH_MAX

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 2048 * ( EVENT_SIZE + 16 ) )
#define MAX_G_STRING_SIZE 64
#define FILE_CACHE_LEN 10

using std::string;
using std::queue;

//control the monitor thread to write and read

extern char file_monitor_cache[FILE_CACHE_LEN][MAX_G_STRING_SIZE];
extern int file_monitor_pos;
extern int last_fetch;
extern sem_t file_full;
extern sem_t file_empty;
extern sem_t file_mutex;


extern int inotify_fd; //global int that stores the inotify_init
extern int MONITOR_TYPE;
extern char * monitor_dirs[1024];


// sem_init(&file_full, 0, 0);
// sem_init(&file_empty, 0, 64);
// sem_init(&file_mutex, 0, 1);




/**
    // 访问 内容修改 属性修改
    IN_ACCESS – File was accessed
    IN_MODIFY – File was modified
    IN_ATTRIB – Metadata changed (permissions, timestamps, extended attributes, etc.)

    // 创建删除
    IN_CREATE – File/directory created in watched directory
    IN_DELETE – File/directory deleted from watched directory
    IN_DELETE_SELF – Watched file/directory was itself deleted

    // 打开关闭
    IN_OPEN – File was opened
    IN_CLOSE_WRITE – File opened for writing was closed
    IN_CLOSE_NOWRITE – File not opened for writing was closed

    IN_MOVE_SELF – Watched file/directory was itself moved
    IN_MOVED_FROM – File moved out of watched directory
    IN_MOVED_TO – File moved into watched directory
*/



void get_all_dir(string root_monitor);
void monitor_files(void *arg);
void remove_monitor();
void write_filemonitor_2cache(const char *source);
void read_filemonitor_4Cache(char dest[][MAX_G_STRING_SIZE], int &cur);
#endif
