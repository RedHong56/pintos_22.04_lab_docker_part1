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

static struct lock sys_lock;

void
syscall_init (void) {

	lock_init(&sys_lock);

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
		break;
	case SYS_EXEC:
		sys_exec(f->R.rdi);
		break;
	case SYS_WAIT:{
		// wait(f->R.rdi);
		break;
	}
	case SYS_HALT:{
		sys_halt();
		break;
	}
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
	case SYS_CLOSE:{
		int fd = f->R.rdi;
		sys_close(fd);
		break;
	}
	case SYS_READ:{
		int fd = f->R.rdi;
		void *buffer = f->R.rsi;
		unsigned length = f->R.rdx;
		f->R.rax = sys_read(fd, buffer, length);
		break;
	}
	case SYS_WRITE:{
		int fd = f->R.rdi;
		const void *buffer = f->R.rsi;
		unsigned length = f->R.rdx;			
		f->R.rax = sys_write(fd, buffer, length);
		break;
	}
	case SYS_FILESIZE:{
		int fd = f->R.rdi;
		f->R.rax = sys_filesize (fd); 
		break;
	}
	// case SYS_FORK:
	// 	sys_fork();
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
////////////////////////////////////HELP///////////////////////////////////////////
void check_address(const uint64_t *address){
	struct thread *curr = thread_current();
	// 주소가 null 인지, 유저 영역인지, 실제 pm에 매핑되어 있는지
	if ( address == NULL || !is_user_vaddr(address) || pml4_get_page(thread_current()->pml4, address) == NULL) 
		sys_exit(-1);
}

void check_valid_string(const char *str) {

	check_address((void *)str); // 시작 주소 검사

    char *ptr = (char *)str;
    while (true) {

        check_address((void *)ptr);

        if (*ptr == '\0') {
            return;
        }
        ptr++;
	}
}

/////////////////////////////////////EXIT////////////////////////////////////////////
void sys_exit (int status){ //이거 중복 선언임
	thread_current()->exit_status = status;
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

	check_address(buffer);

	if (fd<1 || fd > 63)
		return -1;
	
	if (fd == 1){
		if (buffer !=NULL)
		{
			putbuf(buffer, length);
			return length;
		}
		return -1;
	}

	struct file *file_name = thread_current()->fd_set[fd];
	if (file_name == NULL)
		return -1;

	lock_acquire(&sys_lock);
	int ret_length = file_write(file_name, buffer, length);
	lock_release(&sys_lock);

	return ret_length;
}
/////////////////////////////////////HALT////////////////////////////////////////////
void sys_halt (void){
	power_off(); //init.h
}
/////////////////////////////////////CREATE////////////////////////////////////////////
bool sys_create (const char *file, unsigned initial_size){

	check_address(file);
	check_valid_string(file);

	lock_acquire(&sys_lock);
	bool success = filesys_create(file, initial_size); //Inode(명세서)와 Data Block(데이터 공간)할당
	lock_release(&sys_lock);
	return success; 
}
/////////////////////////////////////OPEN////////////////////////////////////////////
int sys_open (const char *file){

	check_address(file);

	if (*file == ""){ // empty 
		return -1;
	}
	
	struct thread *t = thread_current();
	lock_acquire(&sys_lock);
	struct file *file_st = filesys_open(file); // file 이름에 맞는 inode를 dir에서 찾아줌
	lock_release(&sys_lock);
	if (file_st == NULL) // 만약 파일이 존재하지않으면
		return -1;

	for (int fd = 2; fd < 64; fd++){
		if (t->fd_set[fd] == NULL){
			t->fd_set[fd] = file_st;
			return fd;
		}
	}
	file_close(file_st);

	return -1;
}

/////////////////////////////////////CLOSE////////////////////////////////////////////
void sys_close (int fd){
	if (fd<2 || 63<fd){
		sys_exit(-1);
	}
	struct file *close_fd = thread_current()->fd_set[fd];

	if (close_fd == NULL){ // 이게 kick 임
		return;
	}
	lock_acquire(&sys_lock);
	file_close(close_fd);
	lock_release(&sys_lock);

	thread_current()->fd_set[fd] = NULL;
}
//////////////////////////////////////READ///////////////////////////////////////////////
int sys_read (int fd, void *buffer, unsigned length){
	if( fd<0 || fd > 63 || fd == 1 || buffer == NULL)
		return -1;
	
	check_address(buffer); // 주소확인하고
	if(length >0)
		check_address(buffer + length -1); // 끝 주소 확인
	
	if (fd == 0){ //keybord 입력 값 읽기
		uint8_t *buf = (uint8_t *)buffer;
		
		for (unsigned i = 0; i < length; i++){
			buf[i] = input_getc();

			if (buf[i] == NULL)
				return i+1;
		}
		return length;
	}

	struct file *readed_file_name = thread_current()->fd_set[fd];
	if (readed_file_name == NULL)
		return -1;

	lock_acquire(&sys_lock);
	int buf_length = file_read(readed_file_name, buffer, length);
	lock_release(&sys_lock);

	return buf_length;
}

int sys_filesize (int fd){
	if (fd< 1 || 63 < fd)
		return -1;
	
	struct file *file_name = thread_current()->fd_set[fd];
	if (file_name == NULL)
		return -1;
	return(file_length(file_name));
}
// int sys_wait (pid_t){

// }

// pid_t sys_fork (const char *thread_name){

//}
// bool sys_remove (const char *file);


// void sys_seek (int fd, unsigned position);
// unsigned sys_tell (int fd);

