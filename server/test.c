#include "LibLog.h"


int send_data(char* buffer, int len){
	printf("Send: %s\n", buffer);
	return 0;
}

int main()
{
	int i = 0;
	int ret = 0;
	
	initLog(NULL, LOG_DEBUG, 10240, 0);
	setDaemon_s(0);
	ret = setSockFun_s(LOG_TYPE_FUN, &send_data);
	printf("%d\n", ret);
	for (i = 0; i < 100; ++i)
		LogErr("hello world %d", i);

	finiLog_s();
	return 0;
}
