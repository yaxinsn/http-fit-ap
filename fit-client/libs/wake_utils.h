

#ifndef WAKE_UTILS_H
#define WAKE_UTILS_H

typedef struct _wake_utils
{

	int             sockfd[2];//sync
	int             waiting; // 1 is waiting. 0 is working.

}_wake_;

int wake_init(_wake_* w);
void wake_up(_wake_* w);
void sleep_down(_wake_* w);



#endif

