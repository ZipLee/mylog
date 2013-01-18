
#include <sys/types.h>
#include <sys/socket.h>
#include "LibLog.h"

LOG_OPT* g_pLogOpt=NULL;

int writeFd(LOG_OPT * pLogOpt,const char * data);

int writeSock(LOG_OPT * pLogOpt,char * msg);

/*
	use it only if u share the file by any other process/thread, etc..
*/
int createSem(int SemKey, int *pSID)
{
#ifndef SLACKWARE
    union semun {
        int val;
        struct semid_ds *buf;
        ushort *array;
    };  
#endif

    union semun arg;
    int iFirst;  //是否第一次创建

    //初始化信号量
    iFirst=1;
    if ((*pSID = semget(SemKey, 1, 0666 | IPC_CREAT | IPC_EXCL )) <0 ){
        if ((*pSID = semget(SemKey, 1, 0 )) == -1){
            return -1;
        }
        iFirst=0;
    }       

    if (iFirst){
        arg.val=1;  
        if ( semctl(*pSID, 0, SETVAL, arg ) == -1 ){
            return -2;
        }
    }

    return 0;
}

int lockSem(int SID)
{
    struct sembuf sops = {0, -1, SEM_UNDO};

    if (SID==-1)
        return -1;

    if(semop(SID,&sops,1)==-1){
        return -2;
    }

    return 0;       
}

int unlockSem(int SID)
{
    struct sembuf sops = {0, 1, SEM_UNDO};
    size_t nsops = 1;

    if (SID==-1)
        return -1;

    if ( semop(SID, &sops, nsops ) == -1 ){
        return -2;
    }

    return 0;
}

char* getFileName(char* name)
{
	time_t tnow;
	struct tm tm;
	
	if (NULL == name)
		return NULL;
	
	tnow = time(NULL);
	localtime_r(&tnow, &tm);
	sprintf(name, DEFAULT_FILE_NAME, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);	
	
	return name;
}

LOG_OPT* initLog(const char* path, int level, int max_size, int use_sem)
{
	int fd = 0;
	int len = 0;
	time_t tnow;
	struct tm tm;
	key_t ipc_key;
	LOG_OPT* pLogOpt = NULL;
	char* pFilename = NULL;
		

	len = sizeof(LOG_OPT);
	if (NULL == (pLogOpt = (LOG_OPT*)calloc(1, sizeof(LOG_OPT)))){
		printf("init with malloc object NULL\n");
		return NULL;
	}

	if (level < LOG_ERROR || level > LOG_TRACE || max_size <= 0){
		pLogOpt->err_code = LOG_ERR_ARGU_WRONG;
		return NULL;
	}
	pLogOpt->level = level;
	pLogOpt->max_size = max_size;

	if (NULL == (pFilename = (char*)calloc(1, (MAX_LOG_PATH_LEN * sizeof(char))))){
		pLogOpt->err_code = LOG_ERR_MALLOC_NULL;
		return NULL;
	}
	
	if (NULL == path){
		getFileName(pFilename);
	}else{
		snprintf(pFilename, MAX_LOG_PATH_LEN, "%s", path);
	}

	fd = open(pFilename, O_WRONLY|O_APPEND|O_CREAT, 0666); 
	if (fd <= 0){
		close(fd);
		pLogOpt->err_code = LOG_ERR_FD_WRONG;
		return NULL;
	}
	pLogOpt->file_fd = fd;

	ipc_key = ftok(pFilename, 0);
	if (use_sem && ipc_key > 0){
		pLogOpt->sem_flag = use_sem;
		createSem(ipc_key, &(pLogOpt->sem_id));
	}
	
	if (NULL == g_pLogOpt)
		g_pLogOpt = pLogOpt;
	
	return pLogOpt;
}

void finiLog(LOG_OPT* pLogOpt)
{
	if (NULL == pLogOpt)
		return;
	if (pLogOpt->file_name)
		free(pLogOpt->file_name);
	if(pLogOpt->file_fd)
		close(pLogOpt->file_fd);
	if (pLogOpt->sock_fd)
		close(pLogOpt->sock_fd);
	free(pLogOpt);
}

void finiLog_s()
{
	finiLog(g_pLogOpt);
}

int setLevel(LOG_OPT* pLogOpt, int level)
{
	if (NULL == pLogOpt || level < LOG_ERROR || level > LOG_TRACE){		
		pLogOpt->err_code = LOG_ERR_ARGU_WRONG;
		return -1;
	}

	pLogOpt->level = level;
	return 0;
}

int setLevel_s(int level)
{
	return setLevel(g_pLogOpt, level);
}

int setSize(LOG_OPT* pLogOpt, int size)
{
	if (NULL == pLogOpt || size < 0){	
		pLogOpt->err_code = LOG_ERR_ARGU_WRONG;
		return -1;
	}

	pLogOpt->max_size = size;	
	return 0;
}

int setSize_s(int size)
{
	return setSize(g_pLogOpt, size);
}

int setSockfd(LOG_OPT* pLogOpt, int type, int sockfd)
{
	struct sockaddr* sa = NULL;
	int len = sizeof(struct sockaddr);
	
	if (NULL == pLogOpt || 0 == sockfd){	
		pLogOpt->err_code = LOG_ERR_ARGU_WRONG;
		return -1;
	}

	if (LOG_TYPE_TCP != type || LOG_TYPE_UDP != type){
		pLogOpt->err_code = LOG_ERR_TYPE_WRONG;
		return -1;
	}
	
	pLogOpt->sock_type = type;
	pLogOpt->sock_fd = sockfd;

	if (LOG_TYPE_UDP == type){
		if (NULL == (sa = (struct sockaddr*)calloc(1, sizeof(struct sockaddr)))){
			pLogOpt->err_code = LOG_ERR_MALLOC_NULL;
			return -1;
		}
		
		getpeername(sockfd, sa, &len);
		pLogOpt->addr = sa;
		pLogOpt->addr_len = len;
	}
	return 0;
}

int setSockfd_s(int type, int sockfd)
{
	return setSockfd(g_pLogOpt, type, sockfd);
}

int setSockFun(LOG_OPT * pLogOpt,int type,int(* SendFunc)(char * buffer,int len))
{
	if (NULL == pLogOpt){
		pLogOpt->err_code = LOG_ERR_OBJECT_NULL;
		return -1;
	}

	if (LOG_TYPE_FUN != type){
		pLogOpt->err_code = LOG_ERR_ARGU_WRONG;
		return -1;
	}

	pLogOpt->sock_type = type;
	pLogOpt->SendFunc = SendFunc;
	return 0;
}

int setSockFun_s(int type,int(* SendFunc)(char * buffer,int len))
{
	if (NULL == g_pLogOpt){
		g_pLogOpt->err_code = LOG_ERR_OBJECT_NULL;
		return -1;
	}

	if (LOG_TYPE_FUN != type){
		g_pLogOpt->err_code = LOG_ERR_ARGU_WRONG;
		return -1;
	}

	g_pLogOpt->sock_type = type;
	g_pLogOpt->SendFunc = SendFunc;
	return 0;	
}

void setDaemon(LOG_OPT* pLogOpt, int isDaemon)
{
	pLogOpt->is_daemon = isDaemon;
}

void setDaemon_s(int isDaemon)
{
	return setDaemon(g_pLogOpt, isDaemon);
}

int logmsg(LOG_OPT* pLogOpt, int level, const char* fmt, ...)
{
	int ret = -1;
	va_list vl;
	
	if (NULL == pLogOpt){
		pLogOpt->err_code = LOG_ERR_OBJECT_NULL;
		return -1;
	}
	
	if (NULL == fmt || strlen(fmt) <= 0){		
        return 0;
	}

	if (pLogOpt->is_daemon && (level < LOG_ERROR || level > pLogOpt->level))
		return 0;
	
	va_start(vl, fmt);
	ret = vswrite(pLogOpt, fmt, vl);
	va_end(vl);
	return ret;
}

int LogMsg(int level, const char* fmt, ...)
{
	int ret = -1;
	va_list vl;
	
	if (NULL == g_pLogOpt){
		g_pLogOpt->err_code = LOG_ERR_OBJECT_NULL;
		return -1;
	}
	
	if (NULL == fmt || strlen(fmt) <= 0){
        return 0;
	}
	
	if (g_pLogOpt->is_daemon && (level < LOG_ERROR || level > g_pLogOpt->level))
		return 0;
	
	va_start(vl, fmt);
	ret = vswrite(g_pLogOpt, fmt, vl);
	va_end(vl);
	return ret;
}

int logerr(LOG_OPT* pLogOpt, const char* fmt, ...)
{
	int ret = -1;
	va_list vl;
	
	if (NULL == pLogOpt){
		pLogOpt->err_code = LOG_ERR_OBJECT_NULL;
		return -1;
	}
	
	va_start(vl, fmt);
	ret = vswrite(pLogOpt, fmt, vl);
	va_end(vl);
	return ret;	
}

int LogErr(const char* fmt, ...)
{
	int ret = -1;
	va_list vl;
	
	if (NULL == g_pLogOpt){
		g_pLogOpt->err_code = LOG_ERR_OBJECT_NULL;
		return -1;
	}
	
	va_start(vl, fmt);
	ret = vswrite(g_pLogOpt, fmt, vl);
	va_end(vl);
	return ret;		
}

int vswrite(LOG_OPT* pLogOpt, const char* fmt, va_list vl)
{
	int ret = -1;
	char buffer[MAX_SINGLE_MSG_LEN] = {0};
	
	if (NULL == fmt || strlen(fmt) <= 0){	
        return 0;
	}
	
	ret = vsnprintf(buffer, MAX_SINGLE_MSG_LEN, fmt, vl);
	if (ret < 0){
		pLogOpt->err_code = LOG_ERR_STREAM_FAIL;
		return ret;
	}
	
	return writeFd(pLogOpt, buffer);
}

int writeFd(LOG_OPT* pLogOpt, const char* data)
{
	int fd = 0;
	time_t tnow;
	struct tm tm;
	struct tm* ptm;
    struct stat l_stat;
	char time_buf[MAX_TIME_MSG_LEN] = {0};
	char* pFileName = NULL;
	char msg[MAX_SINGLE_MSG_LEN] = {0};
	
	if (NULL == data|| strlen(data) <= 0)
		return 0;
	
	tnow = time(NULL);
	ptm = localtime_r(&tnow, &tm);

	strftime(time_buf, sizeof(time_buf), TIME_FORMAT, ptm);
	snprintf(msg, sizeof(msg), "%s%s%s", time_buf, data, LOG_EOL);

	if (pLogOpt->sem_flag)
		lockSem(pLogOpt->sem_id);
	
	if (0 == pLogOpt->is_daemon){
		printf("%s", msg);
	}

	if (-1 == write(pLogOpt->file_fd, msg, strlen(msg))){
		if (pLogOpt->file_name){
			fd = open(pLogOpt->file_name, O_WRONLY|O_APPEND|O_CREAT, 0666);
			if (fd > 0){
				write(pLogOpt->file_fd, msg, strlen(msg));
				pLogOpt->file_fd = fd;
			}
		}
	}

	if (pLogOpt->sem_flag)
		unlockSem(pLogOpt->sem_id);

	if (NULL != pLogOpt->file_name && pLogOpt->max_size > 0){
		stat(pLogOpt->file_name, &l_stat);
		if (l_stat.st_size > pLogOpt->max_size){
			close(pLogOpt->file_fd);
			free(pLogOpt->file_name);
			if (NULL == (pFileName = (char*)calloc(1, MAX_LOG_PATH_LEN * sizeof(char)))){
				pLogOpt->err_code = LOG_ERR_MALLOC_NULL;
				return -1;
			}
			getFileName(pFileName);
			if ((fd = open(pLogOpt->file_name, O_WRONLY|O_APPEND|O_CREAT, 0666)) < 0){
				pLogOpt->err_code = LOG_ERR_FD_WRONG;
				return -1;
			}
			pLogOpt->file_fd = fd;
			pLogOpt->file_name = pFileName;
		}
	}

	if (pLogOpt->sock_type == LOG_TYPE_TCP || pLogOpt->sock_type == LOG_TYPE_UDP || pLogOpt->sock_type == LOG_TYPE_FUN)
		return writeSock(pLogOpt, msg);
	
	return 0;
}

int writeSock(LOG_OPT* pLogOpt, char* msg)
{
	if (NULL == pLogOpt || NULL == msg)
		return -1;

	if (pLogOpt->sock_fd <= 0)
		return -1;

	if(LOG_TYPE_TCP == pLogOpt->sock_type){
		send(pLogOpt->sock_fd, msg, strlen(msg), MSG_DONTWAIT);
	}else if (LOG_TYPE_UDP == pLogOpt->sock_type){
		sendto(pLogOpt->sock_fd, msg, strlen(msg), MSG_DONTWAIT, pLogOpt->addr, pLogOpt->addr_len);
	}else if (LOG_TYPE_FUN){
		pLogOpt->SendFunc(msg, strlen(msg));
	}else{
		return -1;
	}

	return 0;		
}

void closeFilefd(LOG_OPT* pLogOpt)
{
	close(pLogOpt->file_fd);
	pLogOpt->file_fd = 0;	
}

void closeFilefd_s()
{
	closeSockfd(g_pLogOpt);
}

void closeSockfd(LOG_OPT* pLogOpt)
{
	close(pLogOpt->sock_fd);
	if (LOG_TYPE_UDP == pLogOpt->sock_type){
		pLogOpt->addr_len = 0;
		free(pLogOpt->addr);
		pLogOpt->addr = 0;
	}
	
	pLogOpt->sock_type = LOG_TYPE_ERROR;
	pLogOpt->sock_fd = 0;	
}

void closeSockfd_s()
{
	closeSockfd(g_pLogOpt);
}

int getLogErr(LOG_OPT* pLogOpt)
{
	return pLogOpt->err_code;
}

int getLogErr_s()
{
	return g_pLogOpt->err_code;
}

