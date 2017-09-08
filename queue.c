#include "queue.h"

int queue_is_empty(queue_msg Q)
{
	return Q->size == 0;
}

int queue_is_full(queue_msg Q)
{
	return (Q->size == Q->capacity);
}

void queue_init(queue_msg Q,int size)
{
	int i = 0;
	
	Q->front = Q->rear = 0;
	Q->capacity = size;
	Q->size = 0;

	for (i=0;i<size;i++){
		Q->data[i].array = NULL;
		Q->data[i].len = 0;
	}
}

void queue_free(queue_msg Q)
{
	int i;
	if(queue_is_empty){
		return 0;
	}
	
	for(i = 0;i<MAX_RCEIVE_MSG_LEN;i++){
		if(Q->data[i].array != NULL){
			free(Q->data[i].array);
		}
	}
}

int queue_enqueue(queue_msg Q,void * data,int data_len)
{
	int len = 0;
	int position;
	
	if(queue_is_full(Q)){
		return 1;
	}else{
		if(!data){
			return 2;
		}
		
		len = data_len;
		position = Q->rear;
		Q->data[position].array = malloc(len);
		memcpy(Q->data[position].array,(char *)data,data_len);
		Q->data[position].len = data_len;

		Q->rear = (Q->rear+1) % Q->capacity;
		Q->size = Q->size +1;
	}

	return 0;
}

int queue_dequeue(queue_msg Q,void *data)
{
	int len;
	int position;

	if(queue_is_empty(Q)){
		return 0;
	}
	
	position = Q->front;
	len = Q->data[position].len;
	memcpy(data,Q->data[position].array,len);
	free(Q->data[position].array);
	Q->data[position].array = NULL;

	Q->size = Q->size -1;
	Q->front = (Q->front +1) % Q->capacity;

	return len;
}

