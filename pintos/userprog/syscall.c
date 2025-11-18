#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include <console.h>
#include "threads/init.h" // exit
//create / open
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "user/syscall.h"

#include "threads/synch.h" 

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void sys_halt (void);
void sys_exit (int status);
// tid_t sys_fork (const char *thread_name);
int sys_exec (const char *file);
int sys_wait (tid_t);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned length);
int sys_write (int fd, const void *buffer, unsigned length);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	//%rax시스템 호출 번호 ,인자 순서 %rdi, %rsi, %rdx, %r10, %r8, and %r9
	uint64_t syscall_num = f->R.rax; 
	switch (syscall_num)
	{
	case SYS_EXIT:
		sys_exit(f->R.rdi);
		thread_exit ();
		break;
	case SYS_EXEC:
		sys_exec(f->R.rdi);
		break;
	case SYS_WAIT:
		// wait(f->R.rdi);
		break;
	case SYS_WRITE:
		f->R.rax = sys_write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_HALT:
		sys_halt();
		break;
	case SYS_CREATE:{
		char *file_name = f->R.rdi;
		unsigned size = f->R.rsi;
		f->R.rax = sys_create(file_name, size);
		break;
	}
	case SYS_OPEN:{
		char *file_name = (const char *)f->R.rdi;
		f->R.rax = sys_open(file_name);
		break;
	}
	case SYS_CLOSE:
		int fd = f->R.rdi;
		sys_close(fd);
		break;
	// case SYS_FORK:
	// 	sys_fork();
	// 	break;
	// case SYS_FILESIZE:
	// 	sys_filefize();
	// 	break;
	// case SYS_READ:
	// 	sys_read();
	// 	break;
	// case SYS_SEEK:
	// 	sys_seek();
	// 	break;
	// case SYS_TELL:
	// 	sys_tell();
	// 	break;
	default:
		break;
	}
	// printf ("system call!\n");
	// printf ("%d", syscall_num);
}
/////////////////////////////////////EXIT////////////////////////////////////////////
void sys_exit (int status){ //이거 중복 선언임
	thread_current()->exit_status = status;
	// process_exit();
	thread_exit();
}
/////////////////////////////////////EXEC////////////////////////////////////////////
int sys_exec (const char *file){
	// 이 함수를 호출한 스레드 이름 변경 X , FD는 호출 후에도 열려 있음
	//file -> 실행 cmdlineputbuf()
	//return 성공시 반환 X , 다른 경우 -1
	if (file == NULL)
		return -1;
}
/////////////////////////////////////WRITE////////////////////////////////////////////
int sys_write (int fd, const void *buffer, unsigned length){
	if (fd == 1)
	{
		if (buffer !=NULL)
		{
			putbuf(buffer, length);
			return length;
		}
	}
	return -1;
}
/////////////////////////////////////HALT////////////////////////////////////////////
void sys_halt (void){
	power_off(); //init.h
}
/////////////////////////////////////CREATE////////////////////////////////////////////
bool sys_create (const char *file, unsigned initial_size){
	if (file == NULL ||  !is_user_vaddr(file))
		sys_exit(-1);
	if (pml4_get_page(thread_current()->pml4, file) == NULL)
		sys_exit(-1);
	bool success = filesys_create(file, initial_size); //Inode(명세서)와 Data Block(데이터 공간)할당
	return success; 
}
/////////////////////////////////////OPEN////////////////////////////////////////////
int sys_open (const char *file){

	if (file == NULL ||  !is_user_vaddr(file) || pml4_get_page(thread_current()->pml4, file) == NULL) // bad_ptr
		sys_exit(-1);

	if (*file == "") // empty 
		return -1;
	
	struct thread *t = thread_current();
	struct file *file_st = filesys_open(file); // file 이름에 맞는 inode를 dir에서 찾아줌
	
	if (file_st == NULL) // 만약 파일이 존재하지않으면
		return -1;

	int fd = -1;

	for (int i = 2; i < 64; i++)
	{
		if (t->fd_set[i] == NULL)
		{
			t->fd_set[i] = file_st;
			fd = i;
			break; // twice
		}
	}
	file_close(file_st);
	return fd;
}
/////////////////////////////////////CLOSE////////////////////////////////////////////
void sys_close (int fd){
	//fd 탐색
	if (fd<0 || 64<fd || fd == NULL)
		return;	
	struct file *close_fd = thread_current()->fd_set[fd];
	if (close_fd == NULL || !is_user_vaddr(close_fd)){ // 이게 kick 임
		return;
	}
	file_close(close_fd);
	close_fd = NULL;
}

// void sys_close (int fd) {
//     // 1. 범위 검사 (0: stdin, 1: stdout은 닫지 않도록 2부터 시작)
//     if (fd < 2 || fd > 127) { 
//         return;
//     }
//     struct thread *curr = thread_current();
//     struct file *close_fd = curr->fd_set[fd];
//     if (close_fd == NULL) {
//         return;
//     }
//     file_close(close_fd);
//     curr->fd_set[fd] = NULL; 
// }

//////////////////////////////////////READ///////////////////////////////////////////////


//////////////////////////////////////WRIGHT///////////////////////////////////////////////

// int sys_wait (pid_t){

// }

// pid_t sys_fork (const char *thread_name);
// bool sys_remove (const char *file);

// int sys_filesize (int fd);
// int sys_read (int fd, void *buffer, unsigned length);
// void sys_seek (int fd, unsigned position);
// unsigned sys_tell (int fd);

