#define _GNU_SOURCE
#include <hotdove.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdalign.h>

enum {
  SERVER_FD = 3,
  EPOLL_FD,
  LOCK_FD,
  CLIENT_FD,
  FD_COUNT,
};

enum response_codes {
  RC_LOG,
  RC_RESULT,
};

static int service_uid;
static int service_gid;
static dev_t service_dir_dev;
static ino_t service_dir_ino;

static bool init(bool create){
  struct passwd* pw = getpwnam(hotdove_service_user);
  if(!pw){
    fprintf(stderr, "getpwnam(\"%s\") failed: %d %s\n", hotdove_service_user, errno, strerror(errno));
    return false;
  }
  service_uid = pw->pw_uid;
  service_gid = pw->pw_gid;
  if(chdir(pw->pw_dir)){
    if(!create){
      fprintf(stderr, "chdir(\"%s\") failed: %d %s\n", pw->pw_dir, errno, strerror(errno));
      return false;
    }
    umask(002);
    // This mode is *not* a mistake. We do not want arbitrary users to get read access on the directoy, so they can't take a lock using flock.
    // But we do want them to be able to access the socket file in it, so we do give them search/execute permissions.
    if(mkdir(pw->pw_dir, 0771)){
      fprintf(stderr, "mkdir(\"%s\") failed: %d %s\n", pw->pw_dir, errno, strerror(errno));
      return false;
    }
    if(chdir(pw->pw_dir)){
      fprintf(stderr, "chdir(\"%s\") failed: %d %s\n", pw->pw_dir, errno, strerror(errno));
      return false;
    }
    chown(".", service_uid, service_gid);
  }
  struct stat rds = {0};
  if(stat(".", &rds)){
    perror("stat(.) failed");
    return false;
  }
  if((rds.st_mode & 0444)>>1 != (rds.st_mode & 0222) || rds.st_mode & 06){
    fprintf(stderr,
      "Insecure permissions 0%o on \"%s\", refusing to do anything!\nThis directory is used for locking, and for a permission check. "
      "flock() only needs read permissions, and directories can't be opened with write permissions. This is why to make this secure, "
      "read and write permissions on the directory for users and groups must be the same, and others mustn't have read permissions.\n"
      "The recommended mode for this directory is 0771.\n",
      rds.st_mode & 0777, pw->pw_dir
    );
    return false;
  }
  service_dir_dev = rds.st_dev;
  service_dir_ino = rds.st_ino;
  umask(022);
  return true;
}


static bool daemonize(void){
  pid_t pid = 0;
  int fds[2];
  if(pipe2(fds, O_CLOEXEC)){
    perror("pipe failed");
    return false;
  }
  pid = fork();
  if(pid < 0){
    perror("fork failed");
    close(fds[0]);
    close(fds[1]);
    return false;
  }
  if(pid){
    close(fds[1]);
    uint8_t ret = 1;
    while(read(fds[0], &ret, 1) == -1 && errno == EINTR);
    close(fds[0]);
    if(!ret){
      printf("OK - hotdove started\n");
      exit(0);
    }else{
      return false;
    }
  }
  close(fds[0]);
  setsid();
  pid = fork();
  if(pid < 0){
    perror("fork failed");
    while(write(fds[1],"\x01",1) == -1 && errno == EINTR);
    close(fds[1]);
    return false;
  }
  if(pid){
    close(fds[1]);
    exit(0);
  }
  while(write(fds[1],"\x00",1) == -1 && errno == EINTR);
  close(fds[1]);
  return true;
}

static void stop(void){

}

enum {
  MASK_FD = 0xFFFF,
  MASK_AUTHORIZED = 0x10000,
};

static void dev(const struct hotdove_dev_meta*restrict const m){
  for(int i=0; i<HOTDOVE_PARAM_DEV_COUNT; i++){
    if(!m->p[i]) continue;
    fprintf(stderr, "  %s=%s\n", hotdove_param_dev_s[i], m->p[i]);
  }
}

static bool read_helper(int fd, size_t*const len, unsigned char buf[restrict const *len], int rfd[1]){
  struct msghdr msg = {
    .msg_iov = &(struct iovec){
      .iov_base = buf,
      .iov_len = *len,
    },
    .msg_iovlen = 1,
    .msg_control = (char alignas(struct cmsghdr) [CMSG_SPACE(sizeof(int[1]))]){0},
    .msg_controllen = CMSG_SPACE(sizeof(int[1])),
  };
  ssize_t ret;
  errno = 0;
  while((ret=recvmsg(fd, &msg, MSG_CMSG_CLOEXEC|MSG_WAITALL)) == -1 && errno == EINTR);
  if(ret < 0){
    perror("recvmsg failed");
    return false;
  }
  *len = ret;
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if( cmsg
    && cmsg->cmsg_level == SOL_SOCKET
    && cmsg->cmsg_type == SCM_RIGHTS
    && cmsg->cmsg_len == CMSG_LEN(sizeof(int[1]))
  ){
    int fd;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(int[1]));
    if(!rfd || !ret){
      close(fd);
    }else{
      *rfd = fd;
    }
  }
  return ret;
}

static bool run(void){
  while(true){
    struct epoll_event events[10];
    int nfds = epoll_wait(EPOLL_FD, events, sizeof(events)/sizeof(*events), -1);
    if(nfds == -1){
      if(errno == EINTR)
        continue;
      perror("epoll_wait");
      return false;
    }
    for(int i=0; i<nfds; i++){
      if(events[i].data.u64 == SERVER_FD){
        int client = accept4(SERVER_FD, 0, 0, SOCK_CLOEXEC|SOCK_NONBLOCK);
        if(client == -1){
          perror("accept");
          return false;
        }
        if((client & MASK_FD) != client){
          close(client);
          continue;
        }
        if(epoll_ctl(
          EPOLL_FD, EPOLL_CTL_ADD, client,
          &(struct epoll_event){
            .events = EPOLLIN,
            .data.u64 = client,
          }
        ) == -1){
          perror("epoll_ctl: client");
          return false;
        }
        printf("Got new client %d\n", (int)client);
      }else{
        const int fd = events[i].data.u64 & MASK_FD;
        bool authorized = events[i].data.u64 & MASK_AUTHORIZED;
        uint8_t buf[MAX_MESSAGE_LENGTH];
        int access_token = -1;
        size_t length = sizeof(buf)-1;
        if(!read_helper(fd, &length, buf, &access_token)){
          if(epoll_ctl(EPOLL_FD, EPOLL_CTL_DEL, fd, 0) == -1){
            perror("epoll_ctl: client");
            return false;
          }
          close(fd);
          fprintf(stderr, "Removed connection %d\n", fd);
        }
        if(!authorized && access_token != -1){
          fprintf(stderr, "Got access token %d, verifying it...\n", access_token);
          const int flags = fcntl(access_token, F_GETFL);
          if(flags == -1){
            perror("fcntl(fd, F_GETFL) failed");
            goto auth_check_end;
          }
          if((flags & O_RDONLY) != O_RDONLY)
            goto auth_check_end;
          if((flags & O_PATH) == O_PATH)
            goto auth_check_end;
          // TODO: Check device and inode
          struct stat stat;
          if(fstat(access_token, &stat) == -1){
            perror("fstat failed");
            goto auth_check_end;
          }
          if(stat.st_dev != service_dir_dev)
            goto auth_check_end;
          if(stat.st_ino != service_dir_ino)
            goto auth_check_end;
          fprintf(stderr, "Authorized\n");
          authorized = true;
          if(0) auth_check_end: {
            fprintf(stderr, "Unauthorized\n");
          }
        }
        if(access_token != -1)
          close(access_token);
        buf[length] = 0;
        if(!strcmp((char*)buf, "zap")){
          if(!authorized)
            goto eperm;
          goto done;
        }
        if(!strcmp((char*)buf, "stop")){
          if(!authorized)
            goto eperm;
          stop();
          goto done;
        }
        if(!strcmp((char*)buf, "authorize")){
        }else if(!strcmp((char*)buf, "dev")){
          fprintf(stderr, "[dev]\n");
          if(!authorized)
            goto eperm;
          struct hotdove_dev_meta meta = {0};
          length -= 3;
          for(unsigned char* it=buf+4; length; ){
            if(!--length) break;
            enum hotdove_param_dev_e name = *it++;
            size_t len = strlen((char*)it);
            if(name >= 0 && name < HOTDOVE_PARAM_DEV_COUNT)
              meta.p[name] = (char*)it;
            length -= len + 1;
            it += len + 1;
          }
          dev(&meta);
        }
        if(0) eperm: {
          fprintf(stderr, "Permission denied\n");
        }
      }
    }
  }
done:
  close(EPOLL_FD);
  close(SERVER_FD);
  return true;
}

static bool start(bool forking, bool restart){
  if(!init(true))
    return false;
  const int fdlimit = (int)sysconf(_SC_OPEN_MAX);
  for(int i=3; i<fdlimit; i++)
    close(i);
  int lock = open(".", O_DIRECTORY|O_CLOEXEC);
  if(lock == -1){
    perror("open(.) failed");
    goto err;
  }
  if(lock != LOCK_FD){
    if(dup3(lock, LOCK_FD, O_CLOEXEC)==-1)
      goto err_1;
    close(lock);
    lock = LOCK_FD;
  }
  if(flock(lock, LOCK_EX)){
    perror("flock failed");
    goto err;
  }
  // start of critical section //
  int server = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(server == -1){
    perror("socket");
    goto err_1;
  }
  if(server != SERVER_FD){
    if(dup3(server, SERVER_FD, O_CLOEXEC)==-1)
      goto err_2;
    close(server);
    server = SERVER_FD;
  }
  if(fcntl(server, F_SETFD, FD_CLOEXEC) == -1){
    perror("fcntl(server, F_SETFD, FD_CLOEXEC) failed");
    goto err_2;
  }
  struct sockaddr_un name = {0};
  name.sun_family = AF_UNIX;
  strncpy(name.sun_path, "hotdove.sock", sizeof(name.sun_path)-1);
  bool running = false;
  int res = connect(server, (const struct sockaddr*)&name, sizeof(name));
  if(!res){ // Looks like it's already running!
    running = true;
    if(server != CLIENT_FD){
      if(dup3(server, CLIENT_FD, O_CLOEXEC)==-1)
        goto err_2;
      close(server);
      server = CLIENT_FD;
    }
    hotdove__set_server_fd(server);
    if(!restart){
      printf("OK - hotdove was already running\n");
      close(lock);
      return true;
    }
    server = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if(server == -1){
      perror("socket");
      goto err_1;
    }
    if(fcntl(server, F_SETFD, FD_CLOEXEC) == -1){
      perror("fcntl(server, F_SETFD, FD_CLOEXEC) failed");
      goto err_2;
    }
    if(server != SERVER_FD){
      if(dup3(server, SERVER_FD, O_CLOEXEC)==-1)
        goto err_2;
      close(server);
      server = SERVER_FD;
    }
  }
  name.sun_path[12] = '~';
  if(res && errno != ECONNREFUSED && errno != ENOENT){ // ECONNREFUSED: Application no longer running, socket still there. ENOENT: No socket there.
    perror("connect(hotdove.sock) failed");
    goto err_2;
  }
  if(fcntl(server, F_SETFL, O_NONBLOCK) == -1){
    perror("fcntl(server, F_SETFD, FD_CLOEXEC) failed");
    goto err_2;
  }
  if(unlink("hotdove.sock~") && errno != ENOENT){
    perror("unlink(hotdove.sock~) failed");
    goto err_2;
  }
  if(bind(server, (const struct sockaddr*)&name, sizeof(name))){
    perror("bind(hotdove.sock~) failed");
    goto err_2;
  }
  chmod("hotdove.sock~", 0777);
  if(listen(server, 10)){
    perror("listen failed");
    goto err_2;
  }
  int epollfd = epoll_create1(EPOLL_CLOEXEC);
  if(epollfd == -1){
    perror("epoll_create1");
    goto err_2;
  }
  if(epollfd != EPOLL_FD){
    if(dup3(epollfd, EPOLL_FD, O_CLOEXEC)==-1)
      goto err_3;
    close(epollfd);
    epollfd = EPOLL_FD;
  }
  if(epoll_ctl(
    epollfd, EPOLL_CTL_ADD, server,
    &(struct epoll_event){
      .events = EPOLLIN,
      .data.u64 = server,
    }
  ) == -1) {
    perror("epoll_ctl: server");
    goto err_3;
  }
  if(forking)
    if(!daemonize())
      goto err_3;
  if(running){
    if(!hotdove_stop(true)){
      fprintf(stderr, "hotdove_stop failed\n");
      goto err_3;
    }
    hotdove_cleanup();
  }
  if(rename("hotdove.sock~","hotdove.sock")){
    perror("rename(\"hotdove.sock~\",\"hotdove.sock\") failed");
    goto err_3;
  }
  // end of critical section //
  close(lock);
  if(!forking)
    printf("OK - hotdove is running\n");
  return run();
err_3:
  close(epollfd);
err_2:
  close(server);
err_1:
  close(lock);
err:
  return false;
}

static const struct hotdove_dev_meta* env_get_devmeta(void){
  static bool init;
  static struct hotdove_dev_meta dmeta;
  if(init) return &dmeta;
  for(int i=0; i<HOTDOVE_PARAM_DEV_COUNT; i++)
    dmeta.p[i] = getenv(hotdove_param_dev_s[i]);
  if(!dmeta.p[HOTDOVE_PARAM_DEV_DEVPATH])
    return 0;
  if(!dmeta.p[HOTDOVE_PARAM_DEV_ACTION])
    return 0;
  init = true;
  return &dmeta;
}

int main(int argc, char* argv[]){
  if(argc > 1){
    if(!strcmp(argv[1], "status")){
      return !hotdove_status();
    }else if(!strcmp(argv[1], "run")){
      return !start(false, false);
    }else if(!strcmp(argv[1], "start")){
      return !start(true, false);
    }else if(!strcmp(argv[1], "stop")){
      return !hotdove_stop(false);
    }else if(!strcmp(argv[1], "zap")){
      return !hotdove_stop(true);
    }else if(!strcmp(argv[1], "restart")){
      return !start(true, true);
    }else if(strcmp(argv[1], "dev")){
      goto usage;
    }
  }
  {
    const struct hotdove_dev_meta* dm = env_get_devmeta();
    if(!dm)
      goto usage;
    init(true);
    return !hotdove_dev(dm);
  }
usage:
  fprintf(stderr, "Usage: %s start|stop|restart|status\n", argv[0]);
  fprintf(stderr, "Usage: %s run\n", argv[0]);
  fprintf(stderr, "Usage: DEVPATH=/devices/a/b/c ACTION=add|change|remove SERVICE|SYSTEMD_WANTS|SYSTEMD_READY=\"a b c\" %s\n", argv[0]);
  return 2;
}
