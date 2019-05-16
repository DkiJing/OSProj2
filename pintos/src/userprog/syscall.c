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

static uint32_t *esp;
static void syscall_handler (struct intr_frame *);

/* System call functions */
static void halt(void);
static void exit(int);
static pid_t exec(const char *);
static int wait(pid_t);

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

