#pragma once
#include "afxeditbrowsectrl.h"
#include "Free_Dll_Dialog.h"
#include "PRO_TEXT_Dialog.h"
#include "HS_DATA_DIALOG.h"
#include "afxwin.h"
#include <iostream>
using namespace std;
#define MaxLenSz 0x10000
// ToolAndOpenMore 对话框

class ToolAndOpenMore : public CDialogEx
{
	DECLARE_DYNAMIC(ToolAndOpenMore)

public:
	ToolAndOpenMore(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~ToolAndOpenMore();

// 对话框数据
	enum { IDD = IDD_DIALOG_ToolAndOpenMore };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
private:
	CMFCEditBrowseCtrl mExeFilePath;
	BYTE TextCode[MaxLenSz];
	CListBox mProList;
	unsigned char ProHeader[SZLEN];
	DWORD RVAToolEp;
	unsigned char ProMem[MaxLenSz];
	Free_Dll_Dialog FreeDll;
	PRO_TEXT_Dialog Pro_Text;
	HS_DATA_DIALOG DataHs;
	PVOID PeBuffer;
public:
	void GetToolCode(BYTE* ToolCode, CString strPath);
	afx_msg void OnBnClickedButton6();
	afx_msg void OnBnClickedButton1();
	DWORD FindOpenMoreByCode(DWORD pid, int n);
	BOOL FindOpenMoreByName(DWORD pid);
	BOOL FindOpenMoreByWinName(DWORD pid); 
	BOOL TraverseAllPro(DWORD pid);
	char* getWindowTitleByPid(HWND hwnd, LPARAM lParam);
	void GetHWndsByProcessID(DWORD processID, std::vector<HWND> &vecHWnds);
	BOOL ToolIsRunning(DWORD pid, BYTE* ToolCode);
	BOOL isToolSon(DWORD father, DWORD son);
	DWORD GetProCodeToSZ(DWORD pid);

	afx_msg void OnBnClickedButton2();
};
