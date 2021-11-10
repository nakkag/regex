/*
 * regex.c
 *
 * Copyright (C) 1996-2020 by Ohno Tomoaki. All rights reserved.
 *		https://www.nakka.com/
 *		nakka@nakka.com
 *
 *	参考文献:
 *		「Ｃプログラマのためのアルゴリズムとデータ構造 Part2」
 *		近藤嘉雪 著    ソフトバンク    1993年12月25日発行
 */

 /* Include Files */
#include <windows.h>
#include <tchar.h>

#include "regex.h"

/* Define */
#define ToLower(c)				((c >= TEXT('A') && c <= TEXT('Z')) ? (c - TEXT('A') + TEXT('a')) : c)

#define CHAR_SPACE_SIZE			256
#define EPSILON_TRANS			-1		// ε遷移

#ifndef IS_HIGH_SURROGATE
#define IS_HIGH_SURROGATE(wch)			(((wch) & 0xfc00) == 0xd800)
#define IS_LOW_SURROGATE(wch)			(((wch) & 0xfc00) == 0xdc00)
#define IS_SURROGATE_PAIR(hs, ls)		(IS_HIGH_SURROGATE(hs) && IS_LOW_SURROGATE(ls))
#endif

#ifdef UNICODE
#define IS_LEAD_TBYTE(tb)				IS_HIGH_SURROGATE(tb)
#else
#define IS_LEAD_TBYTE(tb)				IsDBCSLeadByte(tb)
#endif

/* Global Variables */
typedef enum {
	TOKEN_CHAR,						// 通常の文字
	TOKEN_GROUP_OPEN,				// 正規表現のグループ化の開始
	TOKEN_GROUP_CLOSE,				// 正規表現のグループ化の終了
	TOKEN_INTERVAL_ZERO_MORE_NG,	// 任意の数(0を含む)の並び (non-greedy)
	TOKEN_INTERVAL_ONE_MORE_NG,		// 1回以上の並び (non-greedy)
	TOKEN_INTERVAL_ZERO_ONE_NG,		// 0回か1回の並び (non-greedy)
	TOKEN_INTERVAL_CLOSE_NG,		// 繰り返しの指定終了 (non-greedy)
	TOKEN_INTERVAL_ZERO_MORE,		// 任意の数(0を含む)の並び
	TOKEN_INTERVAL_ONE_MORE,		// 1回以上の並び
	TOKEN_INTERVAL_ZERO_ONE,		// 0回か1回の並び
	TOKEN_INTERVAL_OPEN,			// 繰り返しの指定開始
	TOKEN_INTERVAL_CLOSE,			// 繰り返しの指定終了
	TOKEN_ANY_CHAR,					// 改行を除く任意の1文字
	TOKEN_LIST_OPEN,				// 文字リストの指定開始
	TOKEN_LIST_CLOSE,				// 文字リストの指定終了
	TOKEN_LINE_BEGIN,				// 行の先頭
	TOKEN_LINE_END,					// 行の末尾
	TOKEN_ALTERNATION,				// 選択
	TOKEN_META_ESCAPE,				// メタエスケープ
	TOKEN_END,						// トークンの終了
	TOKEN_LIST_NOT,					// 文字リストの否定指定
	TOKEN_LIST_RANGE,				// 文字リストの範囲指定
	TOKEN_LIST_ESCAPE,				// 文字リストのメタエスケープ
	TOKEN_INTERVAL_RANGE,			// 繰り返しの範囲指定
} TOKEN;

static TCHAR* token_chars[] = {
	TEXT("c"),	TEXT("("),	TEXT(")"),	TEXT("*?"),	TEXT("+?"),	TEXT("??"),	TEXT("}?"),
	TEXT("*"),	TEXT("+"),	TEXT("?"),	TEXT("{"),	TEXT("}"),	TEXT("."),	TEXT("["),
	TEXT("]"),	TEXT("^"),	TEXT("$"),	TEXT("|"),	TEXT("\\"),
	TEXT(""),	TEXT("^"),	TEXT("-"),	TEXT("\\"),	TEXT(","),
};

typedef enum {
	OP_CHAR,						// 文字
	OP_ANY_CHAR,					// .
	OP_HEAD,						// 行頭
	OP_TAIL,						// 行末
	OP_CHARCLASS,					// キャラクタクラス
	OP_CONCAT,						// XY
	OP_UNION,						// X|Y
	OP_CLOSURE,						// X*
	OP_CLOSURE_NG,					// X*?
	OP_EMPTY,						// 空
	OP_OPEN,						// (
	OP_CLOSE,						// )
} OP;

typedef struct _TREE {
	OP op;
	union {
		TCHAR* chr_class;
		int i;
		struct {
			TCHAR c1;
			TCHAR c2;
		} c;
		struct {
			struct _TREE* left;
			struct _TREE* right;
		} x;
	} u;
} TREE;

typedef struct _REGEX_PARSER {
	TREE* tree;
	TOKEN current_token;
	TCHAR token_char1;
	TCHAR token_char2;
	TCHAR* p;
	TCHAR user_char_set[CHAR_SPACE_SIZE];
	int intervals_open, intervals_close;
	int rfcnt;
} REGEX_PARSER;

typedef struct _REGEX_MATCH {
	REGEX_NFA* nfa;
	REGEX_REFER* rf;
	BOOL icase;
} REGEX_MATCH;

typedef struct _NFA_STACK {
	NFA_LIST* p;
	TCHAR* c;
	struct _NFA_STACK* next;
} NFA_STACK;

/* Local Function Prototypes */
//memory
static void* mem_alloc(const int size);
static void mem_free(void** mem);
static TCHAR* alloc_copy(const TCHAR* buf);

//string
static TCHAR* str_cpy_n(TCHAR* ret, TCHAR* buf, const int len);
static int str_cmp_n(const TCHAR* buf1, const TCHAR* buf2, const int len);
static int x2d(const TCHAR* str);

//tree
static TCHAR* get_esc_string(TCHAR* c, TCHAR* ret, BOOL expand_flag);
static void get_token(REGEX_PARSER* parser);
static TREE* make_tree_node(REGEX_PARSER* parser, OP op, TREE* left, TREE* right);
static TREE* copy_tree(REGEX_PARSER* parser, TREE* p);
static TREE* primary(REGEX_PARSER* parser);
static TREE* factor(REGEX_PARSER* parser);
static TREE* term(REGEX_PARSER* parser);
static TREE* regexp(REGEX_PARSER* parser);
static REGEX_PARSER* parse(TCHAR* pattern);
static void free_tree(TREE* p);

//NFA
static NFA_LIST* add_transition(REGEX_NFA* nfa, int from, int to, int eps, OP op);
static void generate_nfa(REGEX_NFA* nfa, TREE* tree, int entry, int way_out);
static int generate_nfa_count(TREE* tree);
static REGEX_NFA* build_nfa(REGEX_PARSER* parser);

//match
static BOOL charclass_match(TCHAR* p, TCHAR* c);
static void free_stack(NFA_STACK* ns);
static TCHAR* match_nfa(REGEX_MATCH* rm, TCHAR* c);

/*
 * mem_alloc - バッファを確保
 */
static void* mem_alloc(const int size)
{
	return HeapAlloc(GetProcessHeap(), 0, size);
}

/*
 * mem_free - バッファを解放
 */
static void mem_free(void** mem)
{
	if (*mem != NULL) {
		HeapFree(GetProcessHeap(), 0, *mem);
		*mem = NULL;
	}
}

/*
 * alloc_copy - バッファを確保して文字列をコピーする
 */
static TCHAR* alloc_copy(const TCHAR* buf)
{
	TCHAR* ret;

	if (buf == NULL) {
		return NULL;
	}
	ret = (TCHAR*)mem_alloc(sizeof(TCHAR) * (lstrlen(buf) + 1));
	if (ret != NULL) {
		lstrcpy(ret, buf);
	}
	return ret;
}

/*
 * str_cpy_n - 指定された文字数まで文字列をコピーする
 */
static TCHAR* str_cpy_n(TCHAR* ret, TCHAR* buf, const int len)
{
	int i = len;

	if (buf == NULL || len <= 0) {
		*ret = TEXT('\0');
		return ret;
	}
	while ((*(ret++) = *(buf++)) && --i);
	*ret = TEXT('\0');
	if (i != 0) ret--;
	return ret;
}

/*
 * str_cmp_n - ２つの文字列を文字数分比較を行う
 */
static int str_cmp_n(const TCHAR* buf1, const TCHAR* buf2, const int len)
{
	int i = 0;

	for (; *buf1 == *buf2 && *buf1 != TEXT('\0') && i < len; i++, buf1++, buf2++);
	return ((i == len) ? 0 : *buf1 - *buf2);
}

/*
 * x2d - 16進表記の文字列を数値に変換する
 */
static int x2d(const TCHAR* str)
{
	int num = 0;
	int m;

	for (; *str != TEXT('\0'); str++) {
		if (*str >= TEXT('0') && *str <= TEXT('9')) {
			m = *str - TEXT('0');
		}
		else if (*str >= TEXT('A') && *str <= TEXT('F')) {
			m = *str - TEXT('A') + 10;
		}
		else if (*str >= TEXT('a') && *str <= TEXT('f')) {
			m = *str - TEXT('a') + 10;
		}
		else {
			break;
		}
		num = 16 * num + m;
	}
	return num;
}

/*
 * get_esc_string - エスケープ文字の変換
 */
static TCHAR* get_esc_string(TCHAR* c, TCHAR* ret, BOOL expand_flag)
{
	if (expand_flag == FALSE) {
		switch (*(c + 1)) {
		case TEXT('\\'):
		case TEXT('w'):
		case TEXT('W'):
		case TEXT('d'):
		case TEXT('D'):
		case TEXT('s'):
		case TEXT('S'):
			*ret = *(c++);
			*(ret + 1) = *(c++);
			*(ret + 2) = TEXT('\0');
			return c;
		}
	}

	*(ret + 1) = TEXT('\0');
	c++;

	switch (*c) {
	case TEXT('r'):
	case TEXT('R'):
		*ret = TEXT('\r');
		break;
	case TEXT('n'):
	case TEXT('N'):
		*ret = TEXT('\n');
		break;
	case TEXT('t'):
	case TEXT('T'):
		*ret = TEXT('\t');
		break;
	case TEXT('w'):
		lstrcpy(ret, TEXT("0-9a-zA-Z_"));
		break;
	case TEXT('W'):
		lstrcpy(ret, TEXT("^0-9a-zA-Z_"));
		break;
	case TEXT('d'):
		lstrcpy(ret, TEXT("0-9"));
		break;
	case TEXT('D'):
		lstrcpy(ret, TEXT("^0-9"));
		break;
	case TEXT('s'):
		lstrcpy(ret, TEXT("\t\r\n "));
		break;
	case TEXT('S'):
		lstrcpy(ret, TEXT("^\t\r\n "));
		break;
	default:
		*ret = *c;
		break;
	}
	return (c + 1);
}

/*
 * get_token - トークンの取得
 */
static void get_token(REGEX_PARSER* parser)
{
	TOKEN i;
	int l;
	TCHAR* c;

	parser->token_char1 = TEXT('\0');
	parser->token_char2 = TEXT('\0');
	parser->current_token = TOKEN_CHAR;

	for (i = TOKEN_CHAR + 1; i < TOKEN_END; i++) {
		if (*parser->p == TEXT('\0')) {
			parser->current_token = TOKEN_END;
			return;
		}
		if ((l = lstrlen(*(token_chars + i))) &&
			str_cmp_n(parser->p, *(token_chars + i), l) == 0) {
			parser->current_token = i;
			break;
		}
	}

	c = parser->p;
	parser->p += lstrlen(*(token_chars + parser->current_token));

	switch (parser->current_token) {
	case TOKEN_CHAR:
		parser->token_char1 = *c;
		if (IS_LEAD_TBYTE(*c)) {
			parser->token_char2 = *parser->p++;
		}
		break;
	case TOKEN_ANY_CHAR:
		parser->current_token = TOKEN_ANY_CHAR;
		break;
	case TOKEN_LINE_BEGIN:
		parser->token_char1 = *c;
		break;
	case TOKEN_LINE_END:
		parser->token_char1 = *c;
		break;
	case TOKEN_INTERVAL_OPEN:
		if (*parser->p != TEXT('\0')) {
			int* i = &parser->intervals_open;
			parser->intervals_open = 0;
			parser->intervals_close = 0;
			c = parser->p++;
			while (*c != TEXT('\0')) {
				if (*c == **(token_chars + TOKEN_INTERVAL_CLOSE)) {
					if (i == &parser->intervals_open) {
						parser->intervals_close = parser->intervals_open;
					}
					parser->current_token = TOKEN_INTERVAL_CLOSE;
					break;

				}
				else if (*c == **(token_chars + TOKEN_INTERVAL_RANGE)) {
					i = &parser->intervals_close;
					c = parser->p;
					parser->p++;

				}
				else if (*c >= TEXT('0') && *c <= TEXT('9')) {
					*i = *i * 10 + (*c - TEXT('0'));
					c = parser->p++;

				}
				else {
					c = parser->p++;
				}
			}
		}
		if (parser->current_token != TOKEN_INTERVAL_CLOSE) {
			parser->current_token = TOKEN_END;
		}
		else {
			if (*parser->p == TEXT('?')) {
				parser->current_token = TOKEN_INTERVAL_CLOSE_NG;
				parser->p++;
			}
		}
		break;
	case TOKEN_LIST_OPEN:
		if (*parser->p != TEXT('\0')) {
			int i = 0;
			c = parser->p++;
			if (*c == **(token_chars + TOKEN_LIST_CLOSE)) {
				*(parser->user_char_set + i++) = **(token_chars + TOKEN_LIST_CLOSE);
				c = parser->p;
				parser->p++;
			}
			if (*c == **(token_chars + TOKEN_LIST_NOT) &&
				*parser->p == **(token_chars + TOKEN_LIST_CLOSE)) {
				*(parser->user_char_set + i++) = **(token_chars + TOKEN_LIST_NOT);
				c = parser->p++;
				*(parser->user_char_set + i++) = **(token_chars + TOKEN_LIST_CLOSE);
				c = parser->p++;
			}
			while (*c != TEXT('\0')) {
				if (*c == **(token_chars + TOKEN_LIST_CLOSE)) {
					*(parser->user_char_set + i) = TEXT('\0');
					parser->current_token = TOKEN_LIST_CLOSE;
					break;
				}
				else if (*c == **(token_chars + TOKEN_LIST_ESCAPE)) {
					TCHAR tmp[CHAR_SPACE_SIZE];
					parser->p = get_esc_string(c, tmp, FALSE);
					lstrcpy(parser->user_char_set + i, tmp);
					i += lstrlen(tmp);
				}
				else {
					if (IS_LEAD_TBYTE(*c) == TRUE) {
						*(parser->user_char_set + i++) = *c;
						c = parser->p++;
					}
					*(parser->user_char_set + i++) = *c;
				}
				c = parser->p++;
			}
		}
		if (parser->current_token != TOKEN_LIST_CLOSE) {
			parser->current_token = TOKEN_END;
		}
		break;
	case TOKEN_META_ESCAPE:
		if (*parser->p != TEXT('\0')) {
			parser->p = get_esc_string(c, parser->user_char_set, TRUE);
			parser->current_token = TOKEN_LIST_CLOSE;
			if (lstrlen(parser->user_char_set) == 1) {
				parser->current_token = TOKEN_CHAR;
				parser->token_char1 = *parser->user_char_set;
			}
		}
		break;
	}
}

/*
 * make_tree_node - ノードの作成
 */
static TREE* make_tree_node(REGEX_PARSER* parser, OP op, TREE* left, TREE* right)
{
	TREE* p;

	if ((p = mem_alloc(sizeof(TREE))) == NULL) {
		return NULL;
	}
	ZeroMemory(p, sizeof(TREE));
	p->op = op;
	p->u.x.left = left;
	p->u.x.right = right;
	return p;
}

/*
 * copy_tree - treeのコピー
 */
static TREE* copy_tree(REGEX_PARSER* parser, TREE* p)
{
	TREE* x;

	if (p == NULL) {
		return NULL;
	}
	switch (p->op) {
	case OP_CONCAT:
	case OP_UNION:
		x = make_tree_node(parser, p->op,
			copy_tree(parser, p->u.x.left), copy_tree(parser, p->u.x.right));
		break;
	case OP_CLOSURE:
		x = make_tree_node(parser, p->op,
			copy_tree(parser, p->u.x.left), NULL);
		break;
	case OP_CHAR:
		x = make_tree_node(parser, p->op, NULL, NULL);
		x->u.c.c1 = p->u.c.c1;
		x->u.c.c2 = p->u.c.c2;
		break;
	case OP_CHARCLASS:
		x = make_tree_node(parser, p->op, NULL, NULL);
		x->u.chr_class = alloc_copy(p->u.chr_class);
		break;
	default:
		x = make_tree_node(parser, p->op, NULL, NULL);
		break;
	}
	return x;
}

/*
 * primary - X
 */
static TREE* primary(REGEX_PARSER* parser)
{
	TREE* x = NULL;
	TREE* o, * c;

	switch (parser->current_token) {
	case TOKEN_CHAR:
		// X
		x = make_tree_node(parser, OP_CHAR, NULL, NULL);
		x->u.c.c1 = parser->token_char1;
		x->u.c.c2 = parser->token_char2;
		get_token(parser);
		break;
	case TOKEN_ANY_CHAR:
		// .
		x = make_tree_node(parser, OP_ANY_CHAR, NULL, NULL);
		get_token(parser);
		break;
	case TOKEN_LINE_BEGIN:
		// ^
		x = make_tree_node(parser, OP_HEAD, NULL, NULL);
		x->u.c.c1 = parser->token_char1;
		get_token(parser);
		break;
	case TOKEN_LINE_END:
		// $
		x = make_tree_node(parser, OP_TAIL, NULL, NULL);
		x->u.c.c1 = parser->token_char1;
		get_token(parser);
		break;
	case TOKEN_LIST_CLOSE:
		// [...]
		x = make_tree_node(parser, OP_CHARCLASS, NULL, NULL);
		x->u.chr_class = alloc_copy(parser->user_char_set);
		get_token(parser);
		break;
	case TOKEN_GROUP_OPEN:
		// (...)
		parser->rfcnt++;
		o = make_tree_node(parser, OP_OPEN, NULL, NULL);
		o->u.i = parser->rfcnt;
		c = make_tree_node(parser, OP_CLOSE, NULL, NULL);
		c->u.i = parser->rfcnt;
		get_token(parser);
		x = make_tree_node(parser, OP_CONCAT, o,
			make_tree_node(parser, OP_CONCAT, regexp(parser), c));
		get_token(parser);
		break;
	}
	return x;
}

/*
 * factor - X*
 */
static TREE* factor(REGEX_PARSER* parser)
{
	TREE* p, * r, * x;
	int i;

	x = primary(parser);
	switch (parser->current_token) {
	case TOKEN_INTERVAL_ZERO_MORE:
		// X*
		x = make_tree_node(parser, OP_CLOSURE, x, NULL);
		get_token(parser);
		break;
	case TOKEN_INTERVAL_ZERO_MORE_NG:
		// X*?
		x = make_tree_node(parser, OP_CLOSURE_NG, x, NULL);
		get_token(parser);
		break;
	case TOKEN_INTERVAL_ONE_MORE:
		// X+
		p = copy_tree(parser, x);
		x = make_tree_node(parser, OP_CONCAT, x,
			make_tree_node(parser, OP_CLOSURE, p, NULL));
		get_token(parser);
		break;
	case TOKEN_INTERVAL_ONE_MORE_NG:
		// X+?
		p = copy_tree(parser, x);
		x = make_tree_node(parser, OP_CONCAT, x,
			make_tree_node(parser, OP_CLOSURE_NG, p, NULL));
		get_token(parser);
		break;
	case TOKEN_INTERVAL_ZERO_ONE:
		// X?
		x = make_tree_node(parser, OP_UNION,
			make_tree_node(parser, OP_EMPTY, NULL, NULL), x);
		get_token(parser);
		break;
	case TOKEN_INTERVAL_ZERO_ONE_NG:
		// X??
		x = make_tree_node(parser, OP_UNION, x,
			make_tree_node(parser, OP_EMPTY, NULL, NULL));
		get_token(parser);
		break;
	case TOKEN_INTERVAL_CLOSE:
		// X{n,m}
		if (parser->intervals_close == 0) {
			r = copy_tree(parser, x);
			p = make_tree_node(parser, OP_CLOSURE, r, NULL);
		}
		else {
			p = make_tree_node(parser, OP_EMPTY, NULL, NULL);
		}
		for (i = parser->intervals_close; i > parser->intervals_open; i--) {
			r = copy_tree(parser, x);
			p = make_tree_node(parser, OP_CONCAT, p,
				make_tree_node(parser, OP_UNION,
					make_tree_node(parser, OP_EMPTY, NULL, NULL), r));
		}
		for (i = parser->intervals_open; i > 0; i--) {
			r = copy_tree(parser, x);
			p = make_tree_node(parser, OP_CONCAT, r, p);
		}
		if (parser->intervals_open == 0) {
			p = make_tree_node(parser, OP_UNION,
				make_tree_node(parser, OP_EMPTY, NULL, NULL), p);
		}
		free_tree(x);
		x = p;
		get_token(parser);
		break;
	case TOKEN_INTERVAL_CLOSE_NG:
		// X{n,m}?
		if (parser->intervals_close == 0) {
			r = copy_tree(parser, x);
			p = make_tree_node(parser, OP_CLOSURE_NG, r, NULL);
		}
		else {
			p = make_tree_node(parser, OP_EMPTY, NULL, NULL);
		}
		for (i = parser->intervals_close; i > parser->intervals_open; i--) {
			r = copy_tree(parser, x);
			p = make_tree_node(parser, OP_CONCAT, p,
				make_tree_node(parser, OP_UNION, r,
					make_tree_node(parser, OP_EMPTY, NULL, NULL)));
		}
		for (i = parser->intervals_open; i > 0; i--) {
			r = copy_tree(parser, x);
			p = make_tree_node(parser, OP_CONCAT, r, p);
		}
		if (parser->intervals_open == 0) {
			p = make_tree_node(parser, OP_UNION, p,
				make_tree_node(parser, OP_EMPTY, NULL, NULL));
		}
		free_tree(x);
		x = p;
		get_token(parser);
		break;
	}
	return x;
}

/*
 * term - XY
 */
static TREE* term(REGEX_PARSER* parser)
{
	TREE* x;

	if (parser->current_token == TOKEN_ALTERNATION
		|| parser->current_token == TOKEN_GROUP_CLOSE
		|| parser->current_token == TOKEN_END) {
		x = make_tree_node(parser, OP_EMPTY, NULL, NULL);

	}
	else {
		x = factor(parser);
		while (parser->current_token != TOKEN_ALTERNATION
			&& parser->current_token != TOKEN_GROUP_CLOSE
			&& parser->current_token != TOKEN_END) {
			x = make_tree_node(parser, OP_CONCAT, x, factor(parser));
		}
	}
	return x;
}

/*
 * regexp - X|Y
 */
static TREE* regexp(REGEX_PARSER* parser)
{
	TREE* x;

	x = term(parser);
	while (parser->current_token == TOKEN_ALTERNATION) {
		get_token(parser);
		x = make_tree_node(parser, OP_UNION, term(parser), x);
	}
	return x;
}

/*
 * parse - 構文木の生成
 */
static REGEX_PARSER* parse(TCHAR* pattern)
{
	REGEX_PARSER* parser;

	if ((parser = mem_alloc(sizeof(REGEX_PARSER))) == NULL) {
		return NULL;
	}
	ZeroMemory(parser, sizeof(REGEX_PARSER));

	parser->p = pattern;
	get_token(parser);

	parser->tree = regexp(parser);
	return parser;
}

/*
 * free_tree - 構文木の解放
 */
static void free_tree(TREE* p)
{
	if (p == NULL) {
		return;
	}
	switch (p->op) {
	case OP_CONCAT:
	case OP_UNION:
		free_tree(p->u.x.right);
		p->u.x.right = NULL;
	case OP_CLOSURE:
	case OP_CLOSURE_NG:
		free_tree(p->u.x.left);
		p->u.x.left = NULL;
		break;
	case OP_CHARCLASS:
		mem_free(&p->u.chr_class);
		break;
	default:
		break;
	}
	mem_free(&p);
}

/*
 * add_transition - NFAに状態遷移を追加する
 */
static NFA_LIST* add_transition(REGEX_NFA* nfa, int from, int to, int eps, OP op)
{
	NFA_LIST* p;

	if ((p = mem_alloc(sizeof(NFA_LIST))) == NULL) {
		return NULL;
	}
	ZeroMemory(p, sizeof(NFA_LIST));
	p->eps = eps;
	p->op = op;
	p->to = to;
	p->next = *(nfa->states + from);
	*(nfa->states + from) = p;
	return p;
}

/*
 * generate_nfa - 構文木に対するNFAを生成
 */
static void generate_nfa(REGEX_NFA* nfa, TREE* tree, int entry, int way_out)
{
	NFA_LIST* p;
	int a1, a2;

	if (tree == NULL) {
		return;
	}
	switch (tree->op) {
	case OP_CHAR:
		p = add_transition(nfa, entry, way_out, 0, tree->op);
		if (p != NULL) {
			p->u.c.c1 = tree->u.c.c1;
			p->u.c.c2 = tree->u.c.c2;
		}
		break;
	case OP_ANY_CHAR:
		p = add_transition(nfa, entry, way_out, 0, tree->op);
		break;
	case OP_HEAD:
		if (entry == nfa->entry) {
			nfa->head_flag = TRUE;
			add_transition(nfa, entry, way_out, EPSILON_TRANS, tree->op);
		}
		break;
	case OP_TAIL:
		if (way_out == nfa->exit) {
			nfa->tail_flag = TRUE;
			add_transition(nfa, entry, way_out, EPSILON_TRANS, tree->op);
		}
		break;
	case OP_CHARCLASS:
		p = add_transition(nfa, entry, way_out, 0, tree->op);
		if (p != NULL) {
			p->u.chr_class = alloc_copy(tree->u.chr_class);
		}
		break;
	case OP_OPEN:
	case OP_CLOSE:
		p = add_transition(nfa, entry, way_out, EPSILON_TRANS, tree->op);
		if (p != NULL) {
			p->u.i = tree->u.i;
		}
		break;
	case OP_EMPTY:
		add_transition(nfa, entry, way_out, EPSILON_TRANS, tree->op);
		break;
	case OP_UNION:
		generate_nfa(nfa, tree->u.x.left, entry, way_out);
		generate_nfa(nfa, tree->u.x.right, entry, way_out);
		break;
	case OP_CLOSURE:
		a1 = nfa->nstate++;
		a2 = nfa->nstate++;
		add_transition(nfa, entry, a1, EPSILON_TRANS, tree->op);
		add_transition(nfa, a2, a1, EPSILON_TRANS, tree->op);
		add_transition(nfa, a1, way_out, EPSILON_TRANS, tree->op);
		generate_nfa(nfa, tree->u.x.left, a1, a2);
		break;
	case OP_CLOSURE_NG:
		a1 = nfa->nstate++;
		a2 = nfa->nstate++;
		add_transition(nfa, entry, a1, EPSILON_TRANS, tree->op);
		generate_nfa(nfa, tree->u.x.left, a1, a2);
		add_transition(nfa, a2, a1, EPSILON_TRANS, tree->op);
		add_transition(nfa, a1, way_out, EPSILON_TRANS, tree->op);
		break;
	case OP_CONCAT:
		a1 = nfa->nstate++;
		generate_nfa(nfa, tree->u.x.left, entry, a1);
		generate_nfa(nfa, tree->u.x.right, a1, way_out);
		break;
	default:
		break;
	}
}

/*
 * generate_nfa_count - 生成する状態リストの数の取得
 */
static int generate_nfa_count(TREE* tree)
{
	int ret = 0;

	if (tree == NULL) {
		return 0;
	}
	switch (tree->op) {
	case OP_UNION:
		ret = 0;
		ret += generate_nfa_count(tree->u.x.left);
		ret += generate_nfa_count(tree->u.x.right);
		break;
	case OP_CLOSURE:
		ret = 2;
		ret += generate_nfa_count(tree->u.x.left);
		break;
	case OP_CLOSURE_NG:
		ret = 2;
		ret += generate_nfa_count(tree->u.x.left);
		break;
	case OP_CONCAT:
		ret = 1;
		ret += generate_nfa_count(tree->u.x.left);
		ret += generate_nfa_count(tree->u.x.right);
		break;
	default:
		break;
	}
	return ret;
}

/*
 * build_nfa - NFAの生成
 */
static REGEX_NFA* build_nfa(REGEX_PARSER* parser)
{
	REGEX_NFA* nfa;
	int i;

	// NFA 情報の確保
	if ((nfa = mem_alloc(sizeof(REGEX_NFA))) == NULL) {
		return NULL;
	}
	ZeroMemory(nfa, sizeof(REGEX_NFA));

	// 状態リストの確保
	i = generate_nfa_count(parser->tree);
	nfa->states = mem_alloc(sizeof(NFA_LIST*) * (i + 2));
	ZeroMemory(nfa->states, sizeof(NFA_LIST*) * (i + 2));

	// NFA の生成
	nfa->nstate = 0;
	nfa->entry = nfa->nstate++;
	nfa->exit = nfa->nstate++;
	nfa->head_flag = FALSE;
	nfa->tail_flag = FALSE;
	nfa->rfcnt = parser->rfcnt + 1;
	generate_nfa(nfa, parser->tree, nfa->entry, nfa->exit);
	return nfa;
}

/*
 * free_nfa - NFAの解放
 */
void free_nfa(REGEX_NFA* nfa)
{
	int i;
	NFA_LIST* p, * q;

	if (nfa == NULL) return;

	for (i = 0; i < nfa->nstate; i++) {
		if (*(nfa->states + i) != NULL) {
			p = *(nfa->states + i);
			while (p != NULL) {
				q = p;
				p = p->next;
				if (q->op == OP_CHARCLASS) {
					mem_free(&q->u.chr_class);
				}
				mem_free(&q);
			}
		}
	}
	mem_free((void**)&nfa->states);
	mem_free(&nfa);
}

/*
 * charclass_match - キャラクタクラスのマッチング
 */
static BOOL charclass_match(TCHAR* p, TCHAR* c)
{
	TCHAR tmp[CHAR_SPACE_SIZE];
	BOOL ret = FALSE;
	BOOL neg_flag = FALSE;

	if (*p == **(token_chars + TOKEN_LIST_NOT)) {
		neg_flag = TRUE;
		p++;
	}

	while (*p != TEXT('\0') && ret == FALSE) {
		if (IS_LEAD_TBYTE(*p) == TRUE) {
			if (*(p + 2) == **(token_chars + TOKEN_LIST_RANGE) && IS_LEAD_TBYTE(*(p + 3)) == TRUE) {
				ret = ((unsigned)*c >= (unsigned)*p &&
					(unsigned)*(c + 1) >= (unsigned)*(p + 1) &&
					(unsigned)*c <= (unsigned)*(p + 3) &&
					(unsigned)*(c + 1) <= (unsigned)*(p + 4)) ? TRUE : FALSE;
				p += 4;
			}
			else {
				ret = (*p == *c && *(p + 1) == *(c + 1)) ? TRUE : FALSE;
				p++;
			}
			p++;
			continue;
		}
		if (*(p + 1) == **(token_chars + TOKEN_LIST_RANGE) && *(p + 2) != TEXT('\0')) {
			ret = ((unsigned)*c >= (unsigned)*p &&
				(unsigned)*c <= (unsigned) * (p + 2)) ? TRUE : FALSE;
			p += 2;
		}
		else {
			if (*p == **(token_chars + TOKEN_LIST_ESCAPE) && *(p + 1) != TEXT('\0')) {
				p = get_esc_string(p, tmp, TRUE);
				ret = charclass_match(tmp, c);
				continue;
			}
			else {
				ret = (*p == *c) ? TRUE : FALSE;
			}
		}
		p++;
	}
	return ((neg_flag == FALSE) ? ret : !ret);
}

/*
 * free_stack - スタックの解放
 */
static void free_stack(NFA_STACK* ns)
{
	if (ns == NULL) {
		return;
	}
	free_stack(ns->next);
	mem_free(&ns);
}

/*
 * match_nfa - NFAで文字列のマッチング
 */
static TCHAR* match_nfa(REGEX_MATCH* rm, TCHAR* c)
{
	NFA_LIST* p = *(rm->nfa->states);
	NFA_STACK ns = { 0 };

	while (1) {
		for (; p != NULL; p = p->next) {
			if (p->eps == EPSILON_TRANS) {
				// ε遷移
				switch (p->op) {
				case OP_OPEN:
					if (rm->rf == NULL) {
						break;
					}
					(rm->rf + p->u.i)->st = c;
					break;
				case OP_CLOSE:
					if (rm->rf == NULL) {
						break;
					}
					(rm->rf + p->u.i)->en = c;
					break;
				}
				if (rm->nfa->exit == p->to) {
					if (rm->nfa->tail_flag == TRUE &&
						*c != TEXT('\0') && *c != TEXT('\r') && *c != TEXT('\n')) {
						continue;
					}
					free_stack(ns.next);
					return c;
				}
				NFA_STACK* new_ns = mem_alloc(sizeof(NFA_STACK));
				ZeroMemory(new_ns, sizeof(NFA_STACK));
				new_ns->p = p;
				new_ns->c = c;
				new_ns->next = ns.next;
				ns.next = new_ns;
				p = *(rm->nfa->states + p->to);
				break;
			}

			// 文字の比較
			if (*c == TEXT('\0')) {
				continue;
			}
			if (rm->nfa->tail_flag == TRUE && (*c == TEXT('\r') || *c == TEXT('\n'))) {
				continue;
			}
			if (IS_LEAD_TBYTE(*c) == TRUE && *(c + 1) != TEXT('\0')) {
				// サロゲートペア(マルチバイトの場合は2バイトコード)
				if (p->op == OP_ANY_CHAR ||
					(p->op == OP_CHARCLASS && charclass_match(p->u.chr_class, c) == TRUE) ||
					((p->u.c.c1 == *c && p->u.c.c2 == *(c + 1)))) {
					if (rm->nfa->exit == p->to) {
						if (rm->nfa->tail_flag == TRUE &&
							*(c + 2) != TEXT('\0') && *(c + 2) != TEXT('\r') && *(c + 2) != TEXT('\n')) {
							continue;
						}
						free_stack(ns.next);
						return c + 2;
					}
					NFA_STACK* new_ns = mem_alloc(sizeof(NFA_STACK));
					ZeroMemory(new_ns, sizeof(NFA_STACK));
					new_ns->p = p;
					new_ns->c = c;
					new_ns->next = ns.next;
					ns.next = new_ns;
					p = *(rm->nfa->states + p->to);
					c += 2;
					break;
				}
			} else if (p->op == OP_ANY_CHAR ||
				(p->op == OP_CHARCLASS && charclass_match(p->u.chr_class, c) == TRUE) ||
				(rm->icase == TRUE && ToLower(p->u.c.c1) == ToLower(*c)) ||
				p->u.c.c1 == *c) {
				if (rm->nfa->exit == p->to) {
					if (rm->nfa->tail_flag == TRUE &&
						*(c + 1) != TEXT('\0') && *(c + 1) != TEXT('\r') && *(c + 1) != TEXT('\n')) {
						continue;
					}
					free_stack(ns.next);
					return c + 1;
				}
				NFA_STACK* new_ns = mem_alloc(sizeof(NFA_STACK));
				ZeroMemory(new_ns, sizeof(NFA_STACK));
				new_ns->p = p;
				new_ns->c = c;
				new_ns->next = ns.next;
				ns.next = new_ns;
				p = *(rm->nfa->states + p->to);
				c++;
				break;
			}
		}
		if (p == NULL) {
			if (ns.next == NULL) {
				break;
			}
			NFA_STACK* tmp = ns.next;
			p = tmp->p->next;
			c = tmp->c;
			ns.next = tmp->next;
			mem_free(&tmp);
		}
	}
	return NULL;
}

/*
 * conv_code - コードを文字に変換
 */
static BOOL conv_code(TCHAR* buf)
{
	TCHAR* p, * r, * s;
	TCHAR tmp[10];

	p = buf;
	while (*p != TEXT('\0')) {
#ifdef UNICODE
		if (*p == TEXT('\\') && (*(p + 1) == TEXT('u') || *(p + 1) == TEXT('U')) && *(p + 2) != TEXT('\0')) {
			r = p + 2;
			for (s = r; (s - r) < 4 && ((*s >= TEXT('0') && *s <= TEXT('9'))
				|| (*s >= TEXT('A') && *s <= TEXT('F'))
				|| (*s >= TEXT('a') && *s <= TEXT('f'))); s++);
			str_cpy_n(tmp, r, s - r);
			*(p++) = (TCHAR)x2d(tmp);
			r += s - r;
			lstrcpy(p, r);
		}
		else if (*p == TEXT('\\') && (*(p + 1) == TEXT('x') || *(p + 1) == TEXT('X')) && *(p + 2) != TEXT('\0')) {
			r = p + 2;
			for (s = r; (s - r) < 2 && ((*s >= TEXT('0') && *s <= TEXT('9'))
				|| (*s >= TEXT('A') && *s <= TEXT('F'))
				|| (*s >= TEXT('a') && *s <= TEXT('f'))); s++);
			str_cpy_n(tmp, r, s - r);
			*p = (BYTE)x2d(tmp) << 8;
			r += s - r;
			if (*r == TEXT('\\') && (*(r + 1) == TEXT('x') || *(r + 1) == TEXT('X')) && *(r + 2) != TEXT('\0')) {
				r = r + 2;
				for (s = r; (s - r) < 2 && ((*s >= TEXT('0') && *s <= TEXT('9'))
					|| (*s >= TEXT('A') && *s <= TEXT('F'))
					|| (*s >= TEXT('a') && *s <= TEXT('f'))); s++);
				str_cpy_n(tmp, r, s - r);
				*(p++) |= (BYTE)x2d(tmp);
				r += s - r;
			}
			else {
				p++;
			}
			lstrcpy(p, r);
		}
		else {
			p++;
		}
#else
		if (*p == TEXT('\\') && (*(p + 1) == TEXT('u') || *(p + 1) == TEXT('U')) && *(p + 2) != TEXT('\0')) {
			r = p + 2;
			for (s = r; (s - r) < 4 && ((*s >= TEXT('0') && *s <= TEXT('9'))
				|| (*s >= TEXT('A') && *s <= TEXT('F'))
				|| (*s >= TEXT('a') && *s <= TEXT('f'))); s++);
			str_cpy_n(tmp, r, s - r);
			WCHAR w = (WCHAR)x2d(tmp);
			*(p++) = w >> 8;
			*(p++) = (w & 0x00FF);
			r += s - r;
			lstrcpy(p, r);
		}
		else if (*p == TEXT('\\') && (*(p + 1) == TEXT('x') || *(p + 1) == TEXT('X')) && *(p + 2) != TEXT('\0')) {
			r = p + 2;
			for (s = r; (s - r) < 2 && ((*s >= TEXT('0') && *s <= TEXT('9'))
				|| (*s >= TEXT('A') && *s <= TEXT('F'))
				|| (*s >= TEXT('a') && *s <= TEXT('f'))); s++);
			str_cpy_n(tmp, r, s - r);
			*(p++) = (BYTE)x2d(tmp);
			r += s - r;
			lstrcpy(p, r);
		}
		else {
			p++;
		}
#endif
	}
	return TRUE;
}

/*
 * regex_compile - 正規表現をコンパイル
 */
REGEX_NFA* regex_compile(TCHAR* ptn)
{
	REGEX_PARSER* parser;
	REGEX_NFA* nfa;

	// 構文木の生成
	TCHAR* _ptn = alloc_copy(ptn);
	if (_ptn == NULL) {
		return NULL;
	}
	conv_code(_ptn);
	parser = parse(_ptn);
	mem_free(&_ptn);

	// NFAの生成
	nfa = build_nfa(parser);
	free_tree(parser->tree);
	mem_free(&parser);
	return nfa;
}

/*
 * regex_match - 正規表現のマッチング
 */
int regex_match(REGEX_NFA* nfa, TCHAR* str, REGEX_REFER** rf, BOOL icase)
{
	REGEX_MATCH rm;
	TCHAR* to;
	TCHAR* p;

	to = NULL;

	if (nfa == NULL) {
		return 0;
	}

	ZeroMemory(&rm, sizeof(REGEX_MATCH));
	rm.nfa = nfa;
	rm.icase = icase;
	rm.rf = mem_alloc(sizeof(REGEX_REFER) * nfa->rfcnt);

	p = str;
	while (*p != TEXT('\0')) {
		ZeroMemory(rm.rf, sizeof(REGEX_REFER) * nfa->rfcnt);
		to = match_nfa(&rm, p);
		if (to != NULL) {
			break;
		}
		if (nfa->head_flag == TRUE) {
			for (; *p != TEXT('\0') && *p != TEXT('\r') && *p != TEXT('\n'); p++);
			for (; *p == TEXT('\r') || *p == TEXT('\n'); p++);
		}
		else if (IS_LEAD_TBYTE(*p) == TRUE && *(p + 1) != TEXT('\0')) {
			p += 2;
		}
		else {
			p++;
		}
	}
	if (to == NULL) {
		mem_free(&rm.rf);
		return 0;
	}
	rm.rf->st = p;
	rm.rf->en = to;
	*rf = rm.rf;
	return nfa->rfcnt;
}

/*
 * free_refer - 後方参照リストの解放
 */
void free_refer(REGEX_REFER* rf)
{
	if (rf == NULL) return;
	mem_free(&rf);
}
/* End of source */
