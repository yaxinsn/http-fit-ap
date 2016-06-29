#include <stdio.h>
#include <unistd.h>


int get_cpu_usage()
{
	FILE* fp = NULL;
	char line[200];
	size_t len=200;
	int ret;	

	static unsigned long old_all=0;
	static unsigned long old_idle=0;
	unsigned long user = 0;
	unsigned long nice = 0;
	unsigned long system = 0;
	unsigned long idle = 0;
	unsigned long iowait = 0;
	unsigned long irq = 0;
	unsigned long softirq = 0;

	unsigned long all = 0;
	fp = fopen("/proc/stat", "r");
	if(fp == NULL)
	{
		perror("fopen /proc/stat");
		return -1;
	}
	fgets(line,len,fp);
	sscanf(line,"cpu %lu %lu %lu %lu %lu %lu %lu", 
		&user,&nice,&system,&idle,&iowait,&irq,&softirq);
	all = user+nice+system+iowait+irq+softirq+idle;
	printf("all %lu ,idle %lu old_all %lu old_idle %lu\n",all,idle,old_all,old_idle);
	ret = 100 - (int)(((idle - old_idle)*100)/(all - old_all));
	old_idle = idle;
	old_all = all;
	fclose(fp);
	return ret;
}

int main()
{
	for(;;)
	{
		printf("cpu usage %d \n",get_cpu_usage());
		sleep(5);
	}
	return 0;
}
