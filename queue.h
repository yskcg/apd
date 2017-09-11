#ifndef __QUEUE_H
#define __QUEUE_H
#include "apd.h"

#define MAX_RCEIVE_MSG_LEN 16
typedef struct{
	char *array;
	int len;
}data_type;

#define SIZE_DATA_TYPE sizeof(data_type)

typedef struct {
	int front;
	int rear;
	int size;
	int capacity;
	data_type data[MAX_RCEIVE_MSG_LEN];
}queue;

typedef queue *queue_msg;
typedef queue queue_rev_msg;

extern void queue_init(queue_msg Q,int size);
extern void queue_free(queue_msg Q);
extern int queue_is_empty(queue_msg Q);
extern int queue_is_full(queue_msg Q);
extern int queue_dequeue(queue_msg Q,void *data);
extern int queue_enqueue(queue_msg Q,void * data,int data_len);

#endif
