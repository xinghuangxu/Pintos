#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

void syscall_init (void);

int
sys_open(const char *ufile);

struct file_descriptor
{
  int handle;
  struct file * file;
  struct list_elem elem;
};
#endif /* userprog/syscall.h */
