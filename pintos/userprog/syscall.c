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
#include "threads/palloc.h" 

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

void sys_halt (void);
void sys_exit (int status);
tid_t sys_fork (const char *thread_name, struct intr_frame *f);
int sys_exec (const char *file);
int sys_wait (tid_t);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned length);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);
int dup2(int oldfd, int newfd);



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

// STDIO 매크로
#define STDIN_OBJ  ((struct file *) 0x1) // 표준 입력용 가짜 주소
#define STDOUT_OBJ ((struct file *) 0x2) // 표준 출력용 가짜 주소

struct lock filesys_lock;

void
syscall_init (void) {

	lock_init(&filesys_lock);

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

	case SYS_FORK:{
		char *thread_name = f->R.rdi;
		f->R.rax = sys_fork(thread_name, f);
		break;
	}

	case SYS_EXEC:{
		f->R.rax = sys_exec(f->R.rdi);
		break;
	}	
	case SYS_WAIT:{
		pid_t pid = f->R.rdi;
		f->R.rax = sys_wait(pid);
		break;
	}
	case SYS_SEEK:{
		int fd = f->R.rdi;
		unsigned position = f->R.rsi;
		sys_seek(fd, position);
		break;
	}	
	case SYS_REMOVE:{
		char *file_name = (const char *)f->R.rdi;
		f->R.rax = sys_remove(file_name);
		break;
	}
	case SYS_TELL:{
		int fd = f->R.rdi;
		f->R.rax = sys_tell(fd);
		break;
	}
	case SYS_DUP2:{
		int oldfd = f->R.rdi;
		int newfd = f->R.rsi;
		f->R.rax = dup2(oldfd, newfd);
		break;
	}
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
	if ( address == NULL || !is_user_vaddr(address) || pml4_get_page(thread_current()->pml4, address) == NULL) {
		sys_exit(-1);
	}
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
	struct thread *curr = thread_current();
	curr->exit_status = status;
	printf ("%s: exit(%d)\n", thread_name(), curr->exit_status);
	thread_exit();
}

/////////////////////////////////////WRITE////////////////////////////////////////////
int sys_write (int fd, const void *buffer, unsigned size){

	check_address(buffer);
	// 유효성 검사
	if (fd<0 || FDT_SIZE<= fd){
		return -1;
	}
	struct thread *curr = thread_current();
    struct file *file = curr->fd_set[fd]; // 일단 가져옴

	if (file == STDOUT_OBJ){ // 이전의 fd == 1
        putbuf(buffer, size);
        return size;
    }

	if(file == NULL || file == STDIN_OBJ){
        return -1;
	}
    // 진짜 파일이라면 -> 파일 쓰기
    lock_acquire(&filesys_lock);
    int bytes = file_write(file, buffer, size);
    lock_release(&filesys_lock);
    return bytes;
}
/////////////////////////////////////HALT////////////////////////////////////////////
void sys_halt (void){
	power_off(); //init.h
}
/////////////////////////////////////CREATE////////////////////////////////////////////
bool sys_create (const char *file, unsigned initial_size){
	// 유효성 검사
	check_address(file);
	check_valid_string(file);

	lock_acquire(&filesys_lock);
	bool success = filesys_create(file, initial_size); //Inode(명세서)와 Data Block(데이터 공간)할당
	lock_release(&filesys_lock);
	return success; 
}
/////////////////////////////////////OPEN////////////////////////////////////////////
int sys_open (const char *file){
	// 유효성 검사
	check_address(file);

	if (*file == ""){ // empty 
		return -1;
	}
	
	struct thread *t = thread_current();

	lock_acquire(&filesys_lock);
	struct file *file_st = filesys_open(file); // file 이름에 맞는 inode를 dir에서 찾아줌
	lock_release(&filesys_lock);
	if (file_st == NULL) // 만약 파일이 존재하지않으면
		return -1;

	for (int fd = 2; fd < FDT_SIZE; fd++){
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
	// 유효성 검사
	if (fd<0 || FDT_SIZE<= fd){
		return ;
	}
	struct file *close_fd = thread_current()->fd_set[fd];

	if (close_fd == NULL){ // 이게 kick 임
		return;
	}
	lock_acquire(&filesys_lock);
	file_close(close_fd);
	lock_release(&filesys_lock);

	thread_current()->fd_set[fd] = NULL;
}
//////////////////////////////////////READ///////////////////////////////////////////////
int sys_read (int fd, void *buffer, unsigned size){
	// 유효성 검사
	check_address(buffer);
	if (fd<0 || FDT_SIZE<= fd){
		return -1;
	}

	struct thread *curr = thread_current();
    struct file *file = curr->fd_set[fd]; // 일단 가져옴

	if (file == STDIN_OBJ){ // 이전의 fd == 0 : 키보드 읽기
        char *ptr = (char *)buffer;
        for (unsigned i = 0; i < size; i++) {
            // Pintos의 input_getc()를 사용하여 키보드 입력을 한 글자씩 받음
            *ptr++ = input_getc(); 
        }
        return size;
    }

if (file == STDOUT_OBJ || file == NULL) {
        // 화면 출력용 fd에서 읽을 수는 없음 -> 에러 처리
        return -1;
    }

    // 일반 파일 읽기 (진짜 파일)
    lock_acquire(&filesys_lock);
    // file_read는 내부에서 file 구조체를 참조하므로
    int bytes_read = file_read(file, buffer, size);
    lock_release(&filesys_lock);

    return bytes_read;
}

//////////////////////////////////////FILE SIZE/////////////////////////////////////////////
int sys_filesize (int fd){
	// 유효성 검사
	if (fd< 0 || FDT_SIZE<= fd)
		return -1;
	
	
	struct file *file = thread_current()->fd_set[fd];
	if (file == STDIN_OBJ|| file == STDOUT_OBJ){
		return -1; // 파일 없으니 -1
	}
	if (file == NULL)
		return -1;

	lock_acquire(&filesys_lock);
	int file_size = file_length(file); // 이거 수정
	lock_release(&filesys_lock);
	return file_size;
}
///////////////////////////////////FORK//////////////////////////////////////////////
pid_t sys_fork (const char *thread_name, struct intr_frame *f) {
    return process_fork(thread_name, f);
}
/////////////////////////////////////EXEC////////////////////////////////////////////
int sys_exec (const char *file){
	//return 성공시 반환 X , 다른 경우 -1
	// 유효성 검사
	check_address(file);

	// strlcpy (file_name, file, PGSIZE); //dest , source, size
	char *file_name;
	file_name = palloc_get_page(PAL_ZERO);
	if (file_name == NULL)
		return -1;
	
	bool success = false;
	for (int i = 0; i < PGSIZE; i++){
		check_address(file + i); // 주소 확인 후
		file_name[i] = file[i]; // 안전하면 복사
		if (file[i] == '\0'){
			success = true;
			break;
		}
	}
	
	if (!success){ // 리턴하면 복사 실패
		palloc_free_page(file_name);
		return -1;
	}
	if (process_exec(file_name) == -1) // process_exec 호출 후 free
		sys_exit(-1);

	NOT_REACHED();
}
//////////////////////////////////WAIT//////////////////////////////////////////
int sys_wait (pid_t pid){
	int child_pid;
	child_pid = process_wait(pid);
	
	return child_pid;
}

void sys_seek (int fd, unsigned position){
	struct thread *curr = thread_current();
	// 유효성 검사
    if (fd < 0 || fd >= FDT_SIZE) {
        return;
    }

    // 파일 객체 가져오기
    struct file *file = curr->fd_set[fd];
    
	if (file == STDIN_OBJ|| file == STDOUT_OBJ){
		return;
	}

    // 파일이 존재하면 오프셋 이동
    if (file != NULL) {
		lock_acquire(&filesys_lock);
        file_seek(file, position);
		lock_release(&filesys_lock);
    }
}

bool sys_remove (const char *file){
	// 유효성 검사
	check_address(file);
	
	bool success = false;

	lock_acquire(&filesys_lock);
	success = filesys_remove(file);
	lock_release(&filesys_lock);

	return success;
}
unsigned sys_tell (int fd){
	struct thread *curr = thread_current();
    // fd 유효성 검사
    if (fd < 0 || fd >= FDT_SIZE) {
        return;
    }
	// 파일 객체 가져오기
    struct file *file = curr->fd_set[fd];

	if (file == STDIN_OBJ|| file == STDOUT_OBJ){
		return 0;
	}
	unsigned off =NULL;

	lock_acquire(&filesys_lock);
	off = file_tell(file);
	lock_release(&filesys_lock);

	return off; 
}

int dup2(int oldfd, int newfd){
	struct thread *curr = thread_current();

	// fd 유효성 검사
	if (oldfd < 0 || oldfd >= FDT_SIZE || newfd < 0 || newfd >= FDT_SIZE) {
		return -1;
	}
	// oldfd를 fd 집합에서 찾고 확인
	struct file *old_file = curr->fd_set[oldfd];
	if (old_file == NULL) {
		return -1;
	}
	// oldfd !=newfd 파일이 아니라 num
	if (oldfd == newfd) {
		return -1;
	}

	// newfd 도 확인하기
	if (curr->fd_set[newfd] != NULL) {
		file_close(curr->fd_set[newfd]);
		curr->fd_set[newfd] = NULL;
	}
	// dup하기
	curr->fd_set[newfd] = file_dup2(old_file);

	return newfd;
}	