#pragma once
#include "afxeditbrowsectrl.h"
#include "afxwin.h"
#include <Windows.h>
#define SZLEN 0x400
// HS_DATA_DIALOG 对话框

class HS_DATA_DIALOG : public CDialogEx
{
	DECLARE_DYNAMIC(HS_DATA_DIALOG)

public:
	HS_DATA_DIALOG(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~HS_DATA_DIALOG();
	virtual BOOL OnInitDialog();


	// 对话框数据
	enum { IDD = IDD_DIALOG_HS_DATA };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CMFCEditBrowseCtrl mExeEditBrowse;
	afx_msg void OnEnChangeMfceditbrowse1();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg BOOL TraverseFuncAndData(LPVOID pPeBuffer);
	afx_msg CHAR* DWORDToString(DWORD value);
	afx_msg DWORD FoaToRva(PVOID PeBuffer, DWORD Foa);
	afx_msg DWORD RvaToFoa(PVOID PeBuffer, DWORD Rva);
	afx_msg DWORD ReverseData(DWORD data);
	afx_msg BOOL MemoryToFile(PVOID pPEbuffer, DWORD filesize, LPSTR filePath);
	afx_msg DWORD CharToDword(CHAR* value);
	afx_msg CHAR* CStringToCharSz(CString value);
	//读取PE文件信息到内存中
	LPVOID PEFileToMemory(LPSTR lpszFile);
private:
	//左右两个列表控件
	CListBox mProListLeft;
	CListBox mProListRight;
	//代码段起末地址
	DWORD TextStartAddress;
	DWORD TextEndAddress;
	DWORD DataAddr;
	DWORD DataLen;
	DWORD OEP;
	LPVOID pPeBuffer;
	CString ModExePath;
	//被修改的call地址和数据地址，值为Foa
	DWORD ModFunAddr[1024];
	DWORD ModDataAddr[1024];
	//修改前的值
	BYTE ModFunAddrValue[1024];
	BYTE ModDataAddrValue[1024];
	//PE文件大小
	DWORD FileSize;
	CString ExePath;
	//修改后EXE路径
	char tmpPath[1024];
	DWORD ImageBase;
    struct _FuncHeader
	{
		BYTE p1, p2, p3, p4;

	}FuncHeader, *pFuncHeader;
	//pFuncHeader* pFuncHead;
	struct ModData
	{
		DWORD ModAddr;
		BYTE RealData;
	}AllModData[SZLEN];
	struct FuncData
	{
		DWORD FunAddr;
		BYTE RealData;
	}AllFuncData[SZLEN];
	DWORD lenFun;
	DWORD lenData;
	int IsSelect[SZLEN];
};
