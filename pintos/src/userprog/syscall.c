#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "devices/input.h"
 
/* file_descriptor */
struct file_descriptor
{
  /* unique file descriptor number returns to user process */
  int fd_num;
  /* owner thread's id of open file */
  tid_t owner;
  /* open file */
  struct file *file_struct;
  struct list_elem elem;
};

struct list open_files;
struct lock *fs_lock;

static uint32_t *esp;
static void syscall_handler (struct intr_frame *);

/* System call functions */
static void halt(void);
static void exit(int);
static pid_t exec(const char *);
static int wait(pid_t);
static int write(int, const void *, unsigned);

static struct file_descriptor *get_open_file(int);
static bool is_valid_uvaddr(const void *);

static bool
is_valid_uvaddr(const void *uvaddr)
{
  return (uvaddr != NULL && is_user_vaddr(uvaddr));
}

/* whether the pointer is valid or not */
bool
is_valid_ptr(const void *usr_ptr)
{
  struct thread *cur = thread_current();
  if(is_valid_uvaddr(usr_ptr)){
    return (pagedir_get_page(cur->pagedir, usr_ptr)) != NULL;
  }
  return false;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  esp = f->esp;
  if(!is_valid_ptr(esp) || !is_valid_ptr(esp + 1) ||
     !is_valid_ptr(esp + 2) || is_valid_ptr(esp + 3))
  {
    exit(-1);
  }else{
    int syscall_number = *esp;
    switch(syscall_number)
    {
      case SYS_HALT:
        halt();
        break;
      case SYS_EXIT:
        exit(*(esp + 1));
        break;
      case SYS_EXEC:
        f->eax = exec((char *) *(esp + 1));
        break;
      case SYS_WAIT:
        f->eax = wait(*(esp + 1));
        break;
      case SYS_WRITE:
        f->eax = write(*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        break;
      default:
	break;	
    }
  }
  printf ("system call!\n");
}

void
halt (void)
{
  shutdown_power_off();
}

void
exit (int status)
{
   struct child_status *child;
   struct thread *cur = thread_current();
   struct thread *parent = thread_get_by_id(cur->parent_id);
   if(parent != NULL){
     struct list_elem *e = list_tail(&parent->children);
     while((e = list_prev(e)) != list_head(&parent->children)){
       child = list_entry(e, struct child_status, elem_child_status);
       if(child->child_id == cur->tid){
         lock_acquire(&parent->lock_child);
	 child->is_exit_called = true;
	 child->child_exit_status = status;
	 lock_release(&parent->lock_child);
       } 
     }
   }
   thread_exit();
}

pid_t
exec (const char *cmd_line)
{
  tid_t tid;
  struct thread *cur;
  if(!is_valid_ptr(cmd_line)){
    exit(-1);
  }
  cur = thread_current();
  cur->child_load_status = 0;
  tid = process_execute(cmd_line);
  lock_acquire(&cur->lock_child);
  while(cur->child_load_status == 0){
    cond_wait(&cur->cond_child, &cur->lock_child);
  }
  if(cur->child_load_status == -1){
    tid = -1;
  }
  lock_release(&cur->lock_child);
  return tid;
}

int
wait(pid_t pid)
{
  return process_wait(pid);
}

int
write(int fd, const void *buffer, unsigned size)
{
  struct file_descriptor *fd_struct;
  int status = 0;
  unsigned buffer_size = size;
  void *buffer_tmp = buffer;
  /* check the user memory pointing by buffer are vaild */
  while(buffer_tmp != NULL){
    if(!is_valid_ptr(buffer_tmp))
      exit(-1);
    if(buffer_size > PGSIZE){
      buffer_tmp += PGSIZE;
      buffer_size -= PGSIZE;
    }else if(buffer_size == 0){
      buffer_tmp = NULL;
    }else{
      buffer_tmp = buffer + size - 1;
      buffer_size = 0;
    }
  }
  lock_acquire(&fs_lock);
  if(fd == STDIN_FILENO)
    status = -1;
  else if(fd == STDOUT_FILENO){
    putbuf(buffer, size);
    status = size;
  }else{
    fd_struct = get_open_file(fd);
    if(fd_struct != NULL)
      status = file_write(fd_struct->file_struct, buffer, size);
  }
  lock_release(&fs_lock);
  return status;
}

struct file_descriptor *
get_open_file(int fd)
{
  struct list_elem *e;
  struct file_descriptor *fd_struct;
  e = list_tail(&open_files);
  while((e = list_prev(e)) != list_head(&open_files)){
    fd_struct = list_entry(e, struct file_descriptor, elem);
    if(fd_struct->fd_num == fd)
      return fd_struct;
  }
  return NULL;
}
