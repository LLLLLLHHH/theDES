#pragma once
#ifndef __BOOL_H__
#define __BOOL_H__

typedef enum
{
	false = 0,
	true = 1
} bool;

typedef struct diffop{
	struct diffop *next;
	int hang;
	int lie;
	int num;
}diffop;

#endif