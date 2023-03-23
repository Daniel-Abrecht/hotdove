#define _GNU_SOURCE
#include <hotdove.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdalign.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

const char*const hotdove_param_dev_s[] = {
#define X(I,Y) [I] = #Y,
  HOTDOVE_PARAM_DEV
#undef X
};

#ifndef SERVICE_USER
#define SERVICE_USER "hotdove"
#endif

const char hotdove_service_user[] = SERVICE_USER;

static int get_service_path_fd(void){
  static int fd = -1;
  if(fd != -1)
    return fd;
  struct passwd* pw = getpwnam(hotdove_service_user);
  if(!pw){
    fprintf(stderr, "getpwnam(\"%s\") failed: %d %s\n", hotdove_service_user, errno, strerror(errno));
    return 0;
  }
  fd = open(pw->pw_dir, O_CLOEXEC|O_PATH|O_DIRECTORY);
  if(fd == -1)
    perror("open failed");
  return fd;
}

static int hotdove__server_fd = -1;

int hotdove_connect(void){
  if(hotdove__server_fd != -1)
    return hotdove__server_fd;
  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if(sock == -1){
    perror("socket");
    return -1;
  }
  if(fcntl(sock, F_SETFD, FD_CLOEXEC) == -1){
    perror("fcntl(sock, F_SETFD, FD_CLOEXEC) failed");
    close(sock);
    return -1;
  }
  struct sockaddr_un name;
  memset(&name, 0, sizeof(name));
  name.sun_family = AF_UNIX;
  int dirfd = get_service_path_fd();
  if(dirfd == -1){
    close(sock);
    return -1;
  }
  snprintf(name.sun_path, sizeof(name.sun_path), "/proc/self/fd/%d/%s", dirfd, "hotdove.sock");
  if(connect(sock, (const struct sockaddr*)&name, sizeof(name))){
    close(sock);
    perror("connect(hotdove.sock)");
    return -1;
  }
  return hotdove__server_fd = sock;
}

void hotdove__set_server_fd(int fd){
  hotdove__server_fd = fd;
}

void hotdove_cleanup(void){
  if(hotdove__server_fd != -1)
    close(hotdove__server_fd);
  hotdove__server_fd = -1;
}

bool hotdove__send(size_t length, const char message[restrict length], bool try_authenticate){
  if(length > MAX_MESSAGE_LENGTH)
    return false;
  int sfd = hotdove_connect();
  if(sfd == -1)
    return false;
  int access_token = -1;
  if(try_authenticate){
    int dirfd = get_service_path_fd();
    // A directory can only be opened for reading, not for writing.
    // dirfd is opened O_PATH, we may or may not have read permissions for it.
    // By opening it for reading, we can prove we have read acces to it.
    access_token = openat(dirfd, ".", O_RDONLY|O_CLOEXEC);
  }
  struct msghdr msg = {
    .msg_iov = &(struct iovec){
      .iov_base = (char*)message,
      .iov_len  = length,
    },
    .msg_iovlen = 1,
  };
  if(access_token != -1){
    msg.msg_control = (char alignas(struct cmsghdr) [CMSG_SPACE(sizeof(int[1]))]){0};
    msg.msg_controllen = CMSG_SPACE(sizeof(int[1]));
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int[1]));
    memcpy(CMSG_DATA(cmsg), &access_token, sizeof(int[1]));
  }
  ssize_t ret;
  while((ret=sendmsg(sfd, &msg, 0)) == -1 && errno == EINTR);
  if(access_token != -1)
    close(access_token);
  return ret == (ssize_t)length;
}

bool hotdove_status(void){
  if(hotdove_connect() >= 0){
    printf("OK - hotdove is running\n");
    return true;
  }else{
    printf("NOPE - hotdove isn't running\n");
    return false;
  }
}

bool hotdove_stop(bool zap){
  if(!hotdove__send(zap?3:4, zap?"zap":"stop", true))
    return false;
  return true;
}

bool hotdove_dev(const struct hotdove_dev_meta*const dm){
  char buf[MAX_MESSAGE_LENGTH];
  char *it=buf, *const end=buf+MAX_MESSAGE_LENGTH;
  memcpy(it, "dev", 4); it += 4;
  for(int i=0; i<HOTDOVE_PARAM_DEV_COUNT; i++){
    if(!dm->p[i])
      continue;
    if(it >= end) return false;
    *it++ = i;
    {
      const char *s = dm->p[i];
      do if(it >= end) return false; while((*it++=*s++));
    }
  }
  return hotdove__send(it-buf-1, buf, true);
}
