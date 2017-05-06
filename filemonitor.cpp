#include "filemonitor.h"

void get_all_dir()
{
    DIR * dir;
    struct dirent *entry;
    struct stat statbuf;
    queue<string> dir_monitor_q;

    dir_monitor_q.push(root_monitor);
    string tmp;

    while(!dir_monitor_q.empty())
    {
        tmp = dir_monitor_q.front();
        dir_monitor_q.pop();

        const char *tmp_cstring = tmp.c_str();

        dir = opendir(tmp_cstring);
        if(!dir)
        {
            fprintf (stderr, "Cannot open directory '%s': %s\n",
                     tmp_cstring, strerror (errno));
            exit (EXIT_FAILURE);
        }

        while((entry = readdir(dir)) != NULL)
        {

            if(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
                continue;

#ifdef _DIRENT_HAVE_D_TYPE
            switch (entry->d_type) {
              case DT_DIR:
                  {
                    char path[PATH_MAX];
                    int path_length = snprintf(path, PATH_MAX, "%s/%s", tmp_cstring, entry->d_name);
                    if(path_length >= PATH_MAX )
                    {
                      fprintf (stderr, "Path length has got too long.\n");
                      exit (EXIT_FAILURE);
                    }

                    int wd = inotify_add_watch(inotify_fd, path, MONITOR_TYPE);
                    monitor_dirs[wd] = path;
                    string sub_dir(path);
                    dir_monitor_q.push(sub_dir);
                    printf("enter the sub_dir %s\n", path);
                  }
            }
#else
            stat(entry->d_name, &statbuf);
            if(S_ISDIR(statbuf.st_mode))
            {
              char path[PATH_MAX];
              int path_length = snprintf(path, PATH_MAX, "%s/%s", tmp_cstring, entry->d_name);
              if(path_length >= PATH_MAX )
              {
                fprintf (stderr, "Path length has got too long.\n");
                exit (EXIT_FAILURE);
              }

              int wd = inotify_add_watch(inotify_fd, path, MONITOR_TYPE);
              monitor_dirs[wd] = path;
              string sub_dir(path);
              dir_monitor_q.push(sub_dir);
              printf("enter the read sub_dir func%s\n", path);
            }
#endif

          }
        closedir(dir);
      }



  }


void monitor_files()
{
  int length, i = 0;
  // int inotify_fd;
  // int wd;
  char buffer[EVENT_BUF_LEN];

  const char * MonitorDir = root_monitor.c_str();

  inotify_fd = inotify_init();
  if (inotify_fd < 0) {
    perror("inotify_init");
  }

  /// 添加监测目录(目录事先存在)
  /// wd 与 工作目录 对应, 要保存起来才能知道 wd 对应哪个 监控目录
  int wd = inotify_add_watch(inotify_fd, MonitorDir, MONITOR_TYPE);
  monitor_dirs[wd] = (char *)MonitorDir;
  /// add all childs directory
  get_all_dir();

  // 循环监听
  for ( ; ; )
  {
    i = 0;
    length = read(inotify_fd, buffer, EVENT_BUF_LEN);

    if (length < 0) {
      perror("read");
    }

    while (i < length) {
      struct inotify_event *event = (struct inotify_event *) &buffer[i];
      if (event->len) {
                /// 新建 目录/文件
        if (event->mask & IN_CREATE) {
          if (event->mask & IN_ISDIR) {
            printf("New directory %s/%s created.\n",  monitor_dirs[event->wd], event->name);
            printf("%s\n", monitor_dirs[event->wd]);
            printf("%s\n", event->name);
						char path[PATH_MAX];
            // bzero(path, sizeof(char) * PATH_MAX);
            // strcat(path, monitor_dirs[event->wd]);
            // printf("after 1st strcat :%s\n", path);
            // strcat(path, "/");
            // printf("after 2nd strcat :%s\n", path);
            // strcat(path, event->name);
            // printf("after 3rd strcat :%s\n", path);
            snprintf(path, PATH_MAX, "%s/%s", monitor_dirs[event->wd], event->name);
						int wd = inotify_add_watch(inotify_fd, path, MONITOR_TYPE);
						monitor_dirs[wd] = path;
            printf("adding the path to watch list%s\n", path);
          } else {
            printf("New file %s/%s created.\n", monitor_dirs[event->wd], event->name);
          }
                /// 删除 目录/文件
        } else if ((event->mask & IN_DELETE) || (event->mask & IN_DELETE_SELF)) {
          if (event->mask & IN_ISDIR) {
            printf("Directory %s/%s deleted.\n",  monitor_dirs[event->wd], event->name);
          } else {
            printf("File %s/%s deleted.\n",  monitor_dirs[event->wd], event->name);
          }
                /// 访问 内容修改 属性修改
        } else if (event->mask & IN_ACCESS) {
                    printf("File %s/%s was accessed.\n",  monitor_dirs[event->wd], event->name);
        } else if (event->mask & IN_ATTRIB) {
                    printf("File %s/%s permission was changed.\n",  monitor_dirs[event->wd], event->name);
        } else if (event->mask & IN_MODIFY) {
            if (event->mask & IN_ISDIR) {
            printf("Directory %s/%s was modified.\n",  monitor_dirs[event->wd], event->name);
          } else {
            printf("File %s/%s was modified.\n",  monitor_dirs[event->wd], event->name);
          }
                /// 打开关闭
        } else if (event->mask & IN_OPEN) {
          if (event->mask & IN_ISDIR) {
            printf("Directory %s/%s was opened.\n",  monitor_dirs[event->wd], event->name);
          } else {
            printf("File %s/%s was opened.\n",  monitor_dirs[event->wd], event->name);
          }

        } else if (event->mask & IN_CLOSE_WRITE) {
                    printf("File %s/%s was closed with write.\n",  monitor_dirs[event->wd], event->name);
        } else if (event->mask & IN_CLOSE_NOWRITE) {
                    printf("File %s/%s was closed without write.\n",  monitor_dirs[event->wd], event->name);
        }
      }
      i += EVENT_SIZE + event->len;
    }

  }
}

void remove_monitor()
{
  int count_dir = 0;
  while (monitor_dirs[count_dir] != NULL) {
    inotify_rm_watch(inotify_fd, count_dir);
    count_dir++;
  }
  close(inotify_fd);
}

int main(int argc, char const *argv[]) {
  monitor_files();
  remove_monitor();
  return 0;
}
