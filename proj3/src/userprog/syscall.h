#include <list.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct list file_list;
int descriptor_counter;

struct lock file_list_lock;
struct lock descriptor_counter_lock;

struct file_struct {
	struct list_elem file_struct_elem;
	int descriptor;
	struct file* file;
	struct thread* thread;
};

struct list name_list;

struct name_struct {
	char* name;
	struct list_elem name_elem;
};

#endif /* userprog/syscall.h */
