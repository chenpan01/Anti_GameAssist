#pragma once
#include "afxeditbrowsectrl.h"
#include "afxwin.h"
#include "md5.h"
#include "HS_DATA_DIALOG.h"
#include<string>
// PRO_TEXT_Dialog 对话框

class PRO_TEXT_Dialog : public CDialogEx
{
	DECLARE_DYNAMIC(PRO_TEXT_Dialog)

public:
	PRO_TEXT_Dialog(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~PRO_TEXT_Dialog();

// 对话框数据
	enum { IDD = IDD_DIALOG_Pro_Code };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnEnChangeMfceditbrowse1();
	int GerGangPos(char* pp);
private:
	CString ExePath;
	CString ExePath_Ver;
	CMFCEditBrowseCtrl mExeEditBrowse;
	CMFCEditBrowseCtrl mExeEditBrowse_Ver;
	CListBox mProList;
	string CheckValue="";
	string ProCheckV = "";
	DWORD ImageBase;
	//RVA
	DWORD TextStartAddr;
	//Text Len
	DWORD TextLen;
	//代码段结束地址
	DWORD TextEndAddr;
	
	struct _FuncHeader
	{
		BYTE p1, p2, p3, p4;

	}FuncHeader, *pFuncHeader;

public:
	afx_msg void OnEnChangeMfceditbrowse2();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton3();
	afx_msg BOOL GetImportFilePathAndUserFunc(char* path);
	afx_msg void OnBnClickedButton2();
	
	void AppendCharSZ(DWORD value,char* SzChar);
	void AddProcessToList();
	BOOL IsNameEqual(CString Path1, CString Path2, char pos);
};
