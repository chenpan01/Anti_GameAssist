#pragma once
#include "afxwin.h"
#include<vector>
#include "PRO_TEXT_Dialog.h"
#include "HS_DATA_DIALOG.h"
#include "afxeditbrowsectrl.h"
// Free_Dll_Dialog 对话框
#define MaxLen 0x4000
class Free_Dll_Dialog : public CDialogEx
{
	DECLARE_DYNAMIC(Free_Dll_Dialog)

public:
	Free_Dll_Dialog(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~Free_Dll_Dialog();
	BOOL OnInitDialog();
	void AddProcessToList(CListBox &mProList);
	BOOL IsInjectDll(DWORD dwPid);
// 对话框数据
	enum { IDD = IDD_DIALOG_FreeDll };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);   
	DECLARE_MESSAGE_MAP()
public:
	void GetFileFromDir(CString csDirPath);
	char* SZCharSwapToSmall(char* str);
	char* StringToChar(string str);
	PBYTE GetExeBase(DWORD pid);
	void GetProMemToChar(DWORD pid, unsigned char ans[]);
	BOOL GetAllIatFromPE(CString ProPath);
	void GetFirstHsAndEndHs(DWORD pid, unsigned char ProMem[]);
private:
	
	HS_DATA_DIALOG Datahs;
	PRO_TEXT_Dialog ProText;
	CListBox mProList;
	CString strFilePath;
	DWORD ImageBase;
	//记录IAT表信息
	//DWORD MaxLen = 0x4000;
	DWORD AllIAT[MaxLen];
	CMFCEditBrowseCtrl mProPath;
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnBnClickedButton5();
};
/*struct IATINFO
{
DWORD Addr[SZLEN];
} IatInfo[];*/