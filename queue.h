#ifndef __QUEUE_H
#define __QUEUE_H
#include "apd.h"

typedef struct{
	char *array;
	int len;
}data_type;

typedef struct {
	int front;
	int rear;
	int size;
	int capacity;
	data_type ** data;
}queue;

typedef queue *queue_msg;

#endif
