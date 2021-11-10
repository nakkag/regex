/*
 * regex.h
 *
 * Copyright (C) 1996-2020 by Ohno Tomoaki. All rights reserved.
 *		https://www.nakka.com/
 *		nakka@nakka.com
 */

#ifndef _INC_REGEX_H
#define _INC_REGEX_H

 /* Include Files */
#include <windows.h>
#include <tchar.h>

/* Define */

/* Struct */
//NFAリスト
typedef struct _NFA_LIST {
	int op;
	union {
		TCHAR* chr_class;
		int i;
		struct {
			TCHAR c1;
			TCHAR c2;
		} c;
	} u;
	int eps;
	int to;
	struct _NFA_LIST* next;
} NFA_LIST;

//NFA情報
typedef struct _REGEX_NFA {
	struct _NFA_LIST** states;
	int entry;
	int exit;
	int nstate;
	int rfcnt;
	BOOL head_flag;
	BOOL tail_flag;
} REGEX_NFA;

//後方参照リスト
typedef struct _REGEX_REFER {
	TCHAR* st;
	TCHAR* en;
} REGEX_REFER;

/* Function Prototypes */
REGEX_NFA* regex_compile(TCHAR* ptn);
int regex_match(REGEX_NFA* nfa, TCHAR* str, REGEX_REFER** rf, BOOL icase);
void free_refer(REGEX_REFER* rf);
void free_nfa(REGEX_NFA* nfa);

#endif
/* End of source */
