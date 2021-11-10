
#include <windows.h>
#include <stdio.h>

#include "regex.h"

int main(void)
{
	REGEX_NFA* nfa;
	REGEX_REFER* rf;
	TCHAR buf[256];
	TCHAR* regex;
	TCHAR* p;
	int rc;
	int i;

	//�}�b�`���镶����Ɗ��ʂɑΉ�����������̕\�� (����Q��)
	//�R���p�C��
	regex = TEXT("((abc|bef)[12345]*)xyz");
	_tprintf(TEXT("regex: %s\n"), regex);
	nfa = regex_compile(regex);

	//����
	p = TEXT("sdfabc423xyzaadf");
	_tprintf(TEXT("string: %s\n"), p);
	rc = regex_match(nfa, p, &rf, FALSE);
	if (rc > 0) {
		for (i = 0; i < rc; i++) {
			if (rf[i].st == NULL || rf[i].en == NULL) {
				break;
			}
			lstrcpyn(buf, rf[i].st, rf[i].en - rf[i].st + 1);
			if (i == 0) {
				//�}�b�`����������
				_tprintf(TEXT("match: %s\n"), buf);
			}
			else {
				//���ʂɑΉ�����������
				_tprintf(TEXT("%d: %s\n"), i, buf);
			}
		}
	}
	else {
		_tprintf(TEXT("no match\n"));
	}
	_tprintf(TEXT("\n"));
	free_refer(rf);
	free_nfa(nfa);
	rf = NULL;
	nfa = NULL;

	//�}�b�`������̂�S�ĕ\��
	//�R���p�C��
	regex = TEXT("[^-]*");
	_tprintf(TEXT("regex: %s\n"), regex);
	nfa = regex_compile(regex);

	//����
	p = TEXT("abc-de-f-g");
	_tprintf(TEXT("string: %s\n"), p);
	rc = regex_match(nfa, p, &rf, FALSE);
	while (rc > 0) {
		if (p == rf[0].st && p == rf[0].en) {
			if (*(rf[0].en + 1) == TEXT('\0')) {
				free_refer(rf);
				rf = NULL;
				break;
			}
			p = rf[0].en + 1;
		}
		else {
			//�}�b�`����������̕\��
			lstrcpyn(buf, rf[0].st, rf[0].en - rf[0].st + 1);
			_tprintf(TEXT("match: %s\n"), buf);
			p = rf[0].en;
		}
		free_refer(rf);
		rf = NULL;
		if (nfa->head_flag == TRUE) {
			// ^
			for (; *p != TEXT('\0') && *p != TEXT('\r') && *p != TEXT('\n'); p++);
			for (; *p == TEXT('\r') || *p == TEXT('\n'); p++);
			if (*p == TEXT('\0')) {
				break;
			}
		}
		//���̌���
		rc = regex_match(nfa, p, &rf, FALSE);
	}
	free_refer(rf);
	free_nfa(nfa);
	rf = NULL;
	nfa = NULL;
	return 0;
}
