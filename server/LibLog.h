//-+------------------------------------------------
//-|	LibLog
//-+------------------------------------------------
//-| LibLog support output to both of your display device  and
//-| a specified file. Also, if u use it in a socket server, once u 
//-| give it an appointed socket fd, the log will send to it.
//-+------------------------------------------------
//-| Author : Zip(Lizp0420@gmail.com)
//-+------------------------------------------------

/**
 * @version 1.0
 * @author  $Author
 * @date    2013-01-13
 */
 
#pragma once

#ifndef _LIBLOG_H_
#define _LIBLOG_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <sys/socket.h>

#define TIME_FORMAT	"[%Y-%m-%d %H:%M:%S] "

#define DEFAULT_FILE_NAME "Log_%02d%02d%02d%02d%02d%02d.txt"

#ifndef __WIN32__
#define LOG_EOL		"\n"
#else
#define LOG_EOL		"\r\n"
#endif

#define MAX_LOG_PATH_LEN	256

#define MAX_SINGLE_MSG_LEN	1024

#define MAX_TIME_MSG_LEN	64

#define MAX_ERROR_REASON_LEN	256

enum
{
	LOG_TYPE_TCP,
	LOG_TYPE_UDP,
	LOG_TYPE_FUN,
	LOG_TYPE_ERROR,
};

enum
{
	LOG_ERR_MALLOC_NULL,
	LOG_ERR_OBJECT_NULL,
	LOG_ERR_ARGU_WRONG,
	LOG_ERR_FD_WRONG,
	LOG_ERR_TYPE_WRONG,
	LOG_ERR_STREAM_FAIL,
};

enum
{
	LOG_ERROR,
	LOG_INFO,
	LOG_WARNING,
	LOG_DEBUG,
	LOG_TRACE,
};


struct _LOG_OPT_
{
	int level;
	int file_fd;
	int sock_type;
	int sock_fd;
	int max_size;
	int sem_flag;
	int sem_id;
	int is_daemon;
	int err_code;
	int addr_len;
	int (*SendFunc)(char* buffer, int len);
	char* file_name;
	struct sockaddr* addr;
};

typedef struct _LOG_OPT_ LOG_OPT;

LOG_OPT* initLog(const char * path,int level,int max_size,int use_sem);

void finiLog(LOG_OPT * pLogOpt);

void finiLog_s();

void setDaemon(LOG_OPT* pLogOpt,int isDaemon);

int setLevel(LOG_OPT * pLogOpt, int level);

int setSize(LOG_OPT * pLogOpt, int size);

int setSockfd(LOG_OPT* pLogOpt, int type,int sockfd);

int setSockFun(LOG_OPT* pLogOpt, int type, int (*SendFunc)(char* buffer, int len));

void setDaemon_s(int isDaemon);

int setLevel_s(int level);

int setSize_s(int size);

int setSockfd_s(int type,int sockfd);

int setSockFun_s(int type,int(* SendFunc)(char * buffer,int len));

int logmsg(LOG_OPT* pLogOpt,int level,const char * fmt,...);

int logerr(LOG_OPT* pLogOpt,const char * fmt,...);

int LogMsg(int level,const char * fmt,...);

int LogErr(const char * fmt,...);

void closeSockfd(LOG_OPT* pLogOpt);

void closeSockfd_s();

void closeFilefd(LOG_OPT* pLogOpt);

void closeFilefd_s();

int getLogErr(LOG_OPT* pLogOpt);

int getLogErr_s();

#endif

