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

#include <string.h>
#include <sys/dir.h>	// readdir
#include <limits.h>	// PATH_MAX

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 2048 * ( EVENT_SIZE + 16 ) )
#define MAX_G_STRING_SIZE 64
#define FILE_CACHE_LEN 5

using std::string;
using std::queue;

//control the monitor thread to write and read

char file_monitor_cache[FILE_CACHE_LEN][MAX_G_STRING_SIZE] = {NULL};
int file_monitor_pos = 0;
int last_fetch = 0;
sem_t file_full;
sem_t file_empty;
sem_t file_mutex;

// sem_init(&file_full, 0, 0);
// sem_init(&file_empty, 0, 64);
// sem_init(&file_mutex, 0, 1);

void write_filemonitor_2cache(const char *source)
{
    sem_wait(&file_empty);
    sem_wait(&file_mutex);
    strcpy(file_monitor_cache[file_monitor_pos++], source);
    sem_post(&file_mutex);
    sem_post(&file_full);
}
void read_filemonitor_4Cache(char **dest, int &cur)
{

    sem_wait(&file_full);
    sem_wait(&file_mutex);
    while (last_fetch < file_monitor_pos) {
      strcpy(dest[cur], file_monitor_cache[last_fetch]);
      last_fetch++;
      cur++;
    }
    file_monitor_pos = last_fetch = 0;
    sem_post(&file_mutex);
    sem_post(&file_empty);
}

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
bool MONITOR_CONTROL = true;
int inotify_fd; //global int that stores the inotify_init
int MONITOR_TYPE =  IN_CREATE | IN_DELETE | IN_DELETE_SELF | \
                    IN_ACCESS | IN_ATTRIB | IN_MODIFY | IN_OPEN;
char * monitor_dirs[1024];
string root_monitor("/home/hu/test");



void get_all_dir(const char *dir_name);
void monitor_files();
void remove_monitor();
#endif
