#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include <string.h>

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static int write(int fd, const void* buffer, unsigned size);
static void exit(int status);
static void close (int fd);
static void is_valid_ptr(const void *vaddr);
static bool create(const char* file, unsigned initial_size);
static int open(const char* file);
static int filesize(int fd);
static int read(int fd, void* buffer, unsigned size);
static struct file_struct* get_file_struct_from_descriptor(int fd);
static pid_t exec (const char *cmd_line);
static int wait(pid_t pid);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&file_list);
  lock_init (&file_list_lock);
  lock_init (&descriptor_counter_lock);
  list_init(&name_list);
  //this needs to be initialized
  //0 and 1 are reserved
  descriptor_counter = 2;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("system call!\n");
  /*
  SYS_HALT, // Halt the operating system. 
SYS_EXIT, // Terminate this process. 
SYS_EXEC, // Start another process. 
SYS_WAIT, // Wait for a child process to die. 
SYS_CREATE, // Create a file. 
SYS_REMOVE, // Delete a file. 
SYS_OPEN, // Open a file. 
SYS_FILESIZE, // Obtain a file’s size. 
SYS_READ, /// Read from a file. 
SYS_WRITE, // Write to a file. 
SYS_SEEK, // Change position in a file.
SYS_TELL, // Report current position in a file.
SYS_CLOSE,*/

/* in vaddr.h, !is_user_vaddr(f->esp) && !is_kernel_vaddr(f->esp) to check to see if in address space
in pagedir.c, check it has a mapping by using lookup_page, but not sure what to pass it
check (f->esp) != 0
*/

// can't dereference void pointer
// void pointer is way of being able to do template
// void pointer, can pass in int*, char*, any pointer
is_valid_ptr((int*)f->esp);

// Cannot be NULL, Cannot be kernel memory, Cannot be unmapped memory, Cannot be a bad pointer
  
  int sys_code = *(int*)f->esp;
  //printf("sys_code is %i \n", sys_code);
  if (sys_code == SYS_HALT) {
    shutdown_power_off();
    return;
  } else if (sys_code == SYS_EXIT) {
  	is_valid_ptr(((int*)f->esp + 1));
    int status = *((int*)f->esp + 1);
    exit(status);
  } else if (sys_code == SYS_EXEC) {
    is_valid_ptr(*(char**)(f->esp + 4));
    char* cmd_line = *(char**)(f->esp + 4);
    f->eax = exec(cmd_line);
  } else if (sys_code == SYS_WAIT) {
  	is_valid_ptr(((pid_t*)f->esp + 1));
    pid_t pid = *((pid_t*)f->esp + 1);
    f->eax = wait(pid);
  }else if (sys_code == SYS_CREATE) {
    is_valid_ptr(*(char**)(f->esp + 4));
    char* file = *(char**)(f->esp + 4);
    is_valid_ptr(((int*)f->esp + 2));
	int size = *((int*)f->esp + 2);
    f->eax = create(file, size);
    return;
  }else if (sys_code == SYS_REMOVE) {
  	//printf("in sys remove!!!\n")
  }else if (sys_code == SYS_OPEN) {
  	is_valid_ptr(*(char**)(f->esp + 4));
    char* file = *(char**)(f->esp + 4);
    f->eax = open(file);
  }else if (sys_code == SYS_FILESIZE) {
  	is_valid_ptr(((int*)f->esp + 1));
    int fd = *((int*)f->esp + 1);
    f->eax = filesize(fd);
    return;
  }else if (sys_code == SYS_READ) {
    is_valid_ptr(((int*)f->esp + 1));
    int fd = *((int*)f->esp + 1);
    //check before we deference, every time
    is_valid_ptr((int*)f->esp + 2);
    void* buffer = (void*)(*((int*)f->esp + 2));
    is_valid_ptr(buffer);
    is_valid_ptr((unsigned*)f->esp + 3);
    unsigned size = *((unsigned*)f->esp + 3);
    f->eax = read(fd, buffer, size);
  }else if (sys_code == SYS_WRITE) {
  	is_valid_ptr(((int*)f->esp + 1));
    int fd = *((int*)f->esp + 1);
    is_valid_ptr((void*)(*((int*)f->esp + 2)));
    void* buffer = (void*)(*((int*)f->esp + 2));
    is_valid_ptr(((unsigned*)f->esp + 3));
    unsigned size = *((unsigned*)f->esp + 3);
    f->eax = write(fd, buffer, size);
    //if (fd > 1)
    //	printf("write returns %i \n", f->eax);
  }else if (sys_code == SYS_SEEK) {
  	is_valid_ptr(((int*)f->esp + 1));
    int fd = *((int*)f->esp + 1);
    is_valid_ptr((unsigned*)f->esp + 2);
    unsigned position = *((unsigned*)f->esp + 2);
    seek(fd, position);
  }else if (sys_code == SYS_TELL) {
    int fd = *((int*)f->esp + 1);
    is_valid_ptr(((int*)f->esp + 1));
    f->eax = tell(fd);
  }else if (sys_code == SYS_CLOSE) {
  	is_valid_ptr(((int*)f->esp + 1));
    int fd = *((int*)f->esp + 1);
    close(fd);
  } else {
    //printf("nothing found");
  }
  //thread_exit ();
}

static void is_valid_ptr(const void *vaddr) {
  if (vaddr == NULL || !is_user_vaddr(vaddr) || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) {
    //do we neeed to return false instead and make this a boolean?
    exit(-1);
  }
}
/*Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written,
which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented
by the basic file system. The expected behavior is to write as many bytes as possible up to
end-of-file and return the actual number written, or 0 if no bytes could be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of buffer in
one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is
reasonable to break up larger buffers.) Otherwise, lines of text output by different processes
may end up interleaved on the console, confusing both human readers and our grading
scripts.*/
int write(int fd, const void* buffer, unsigned size) {
  /*you will need to implement write system call for STDOUT_FILENO with putbuf too(it is invoked when 
  user program calls printf, otherwise, you can't see output of user program). */
  // write size bytes from buffer to open file fd
  /*if (size == 0) {
    //printf("zero bytes\n");
    return 0;
  } */

  if (fd == STDOUT_FILENO) {
    //printf("here\n");
    putbuf((char*)buffer, (size_t)size);
    return (int)size;
  }

  lock_acquire(&file_list_lock);
  struct file_struct* fs = get_file_struct_from_descriptor(fd);
    struct file* f = NULL;
    if (fs != NULL) {
    	f = fs->file;
    }
    lock_release(&file_list_lock);
    if (f == NULL) {
    	return 0;
    }
  return file_write (f, buffer, size);



  //struct file* f = GET THE FILE FOR THIS ID
  // printf("size is %i\n", size);
  // one call to putbuf(buffer, size)
  //return 0;
}

int wait(pid_t pid) {
  // if can't find a thread with that id, or if some other thread is the parent
  
  // MOVE INTO PROCESS WAIT

  
   return process_wait(pid);
}


/*Changes the next byte to be read or written in open file fd to position, expressed in
bytes from the beginning of the file. (Thus, a position of 0 is the file’s start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes,
indicating end of file. A later write extends the file, filling any unwritten gap with
zeros. (However, in Pintos files have a fixed length until project 4 is complete, so
writes past end of file will return an error.) These semantics are implemented in the
file system and do not require any special effort in system call implementation. */
void seek (int fd, unsigned position) {
  lock_acquire(&file_list_lock);
  struct file_struct* fs = get_file_struct_from_descriptor(fd);
    struct file* f = fs->file;
    lock_release(&file_list_lock);
  file_seek (f, position);
}
/*Returns the position of the next byte to be read or written in open file fd, expressed
in bytes from the beginning of the file.*/
unsigned tell (int fd) {
  lock_acquire(&file_list_lock);
  struct file_struct* fs = get_file_struct_from_descriptor(fd);
    struct file* f = fs->file;
    lock_release(&file_list_lock);
  return file_tell(f);
}


/*Terminates the current user program, returning status to the kernel. If the process’s parent
waits for it (see below), this is the status that will be returned. Conventionally, a status of 0
indicates success and nonzero values indicate errors.*/
void exit(int status) {
	//makprintf("in exit\n");
  thread_current()->exit_status = status;
  thread_exit();
}

// file systems: halt, then create, wait and exec are complicated
// involve locking and file system memory

// keep track of what files have what file descriptors
// do that through a list in syscall.c, doesn't need to be accessed by anyone else
// structs have descriptor, identifier, file itself, list element, and thread
// that created the file

// open and close do the management
// open: create struct
// close: remove struct
// rest of struct takes descriptor, sees if it exists in list, if not return -1 or exit

bool create(const char* file, unsigned initial_size) {
	if (strlen(file) == 0) {
		exit(-1);
	}
	struct list_elem *e;
	  for (e = list_begin (&name_list); e != list_end (&name_list);
	       e = list_next (e))
	    {
	      struct name_struct *ns = list_entry (e, struct name_struct, name_elem);
	      if (strcmp(ns->name, file) == 0) {
	      	//printf("found another file with name\n");
	        return false;
	      }
	    }
	bool created = filesys_create (file, initial_size);
	if (created) {
		struct name_struct* ns = malloc(sizeof(struct name_struct));
		ns->name = file;
		list_push_back(&name_list, &ns->name_elem);
	}
	return created;
}

/*Opens the file called file. Returns a nonnegative integer handle called a "file descriptor"
(fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console: fd 0 (STDIN_FILENO) is
standard input, fd 1 (STDOUT_FILENO) is standard output. The open system call will never
return either of these file descriptors, which are valid as system call arguments only as explicitly
described below.*/
int open(const char* file_) {
	if (file_ == NULL || strlen(file_) == 0) {
    return -1;
  }
  //printf("file name is %s\n", file_);
  struct file * open_file = filesys_open(file_);
  // check to see if file exists
  if (open_file == NULL) {
  	//printf("exiting\n");
  	return -1;
  }

  // create struct
  struct file_struct *fs = malloc(sizeof(struct file_struct));
  //if (fs != NULL) {
    fs->thread = thread_current();
    fs->file = open_file;
    // acquire lock and increment descriptor counter
    lock_acquire (&descriptor_counter_lock);
    fs->descriptor = descriptor_counter;
    descriptor_counter++;
    lock_release(&descriptor_counter_lock);
    
    lock_acquire (&file_list_lock);

    list_push_back (&file_list, &fs->file_struct_elem);
      lock_release(&file_list_lock);
      
     return fs->descriptor;
    
}

// Returns the size, in bytes, of the file open as fd
int filesize(int fd) {
    lock_acquire(&file_list_lock);
  struct file_struct* fs = get_file_struct_from_descriptor(fd);
    struct file* f = fs->file;
    lock_release(&file_list_lock);

  if (f != NULL) {
    return file_length(f);
  }
    return -1;

}

struct file_struct* get_file_struct_from_descriptor(int fd) {
  struct list_elem *e;
  for (e = list_begin (&file_list); e != list_end (&file_list);
       e = list_next (e))
    {
      struct file_struct *fs = list_entry (e, struct file_struct, file_struct_elem);
      if (fs->descriptor == fd) {
        return fs;
      }
    }
    return NULL;
}

/*Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of
file). Fd 0 reads from the keyboard using input_getc().*/
int read(int fd, void* buffer, unsigned size) {
	// check if stdout

	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return (int)size;
		//exit(0);
	}
  lock_acquire(&file_list_lock);
  struct file_struct* fs = get_file_struct_from_descriptor(fd);
  struct file *f = NULL;
  if (fs != NULL) {
  	f = fs->file;
  }
  lock_release(&file_list_lock);

  // must do some checks before this!
  if (f != NULL)
    return file_read(f, buffer, size);
  return -1;
}


/*Closes file descriptor fd. Exiting or terminating a process implicitly closes all 
its open file descriptors, as if by calling this function for each one.*/
void close (int fd) {
  lock_acquire (&file_list_lock);
  struct file_struct* fs = get_file_struct_from_descriptor(fd);

  //multiple descriptors?
  if (fs != NULL) {
    struct file* f = fs->file;
    file_close(f);
    //remove it from the list, then delete it
    //lock_acquire(&file_descriptor_lock);
    struct list_elem *e;
    struct list_elem *e_to_delete = NULL;
    for (e = list_begin (&file_list); e != list_end (&file_list);
         e = list_next (e))
      {
        struct file_struct *fs2 = list_entry (e, struct file_struct, file_struct_elem);
        if (fs2 == fs) {
          e_to_delete = e;
        }
      }
      if (e_to_delete != NULL) {
        list_remove(e_to_delete);
      }
    //lock_release(&file_descriptor_lock);
  }
  lock_release (&file_list_lock);
    

}
/*Runs the executable whose name is given in cmd line, passing any given arguments,
and returns the new process’s program id (pid). Must return pid -1, which otherwise
should not be a valid pid, if the program cannot load or run for any reason. Thus,
the parent process cannot return from the exec until it knows whether the child
process successfully loaded its executable. You must use appropriate synchronization
to ensure this.*/
pid_t exec(const char *cmd_line) {
  return process_execute(cmd_line);
}