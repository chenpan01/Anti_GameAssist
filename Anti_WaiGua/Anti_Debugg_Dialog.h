#pragma once
#include "afxeditbrowsectrl.h"
#include "Anti_WaiGua.h"
#include "ToolAndOpenMore.h"
#include "afxdialogex.h"
#include "Free_Dll_Dialog.h"
#include "PRO_TEXT_Dialog.h"
#include <TlHelp32.h>
#include "HS_DATA_DIALOG.h"


// Anti_Debugg_Dialog 对话框

class Anti_Debugg_Dialog : public CDialogEx
{
	DECLARE_DYNAMIC(Anti_Debugg_Dialog)

public:
	Anti_Debugg_Dialog(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~Anti_Debugg_Dialog();
	BOOL OnInitDialog();
	

// 对话框数据
	enum { IDD = IDD_DIALOG_AntiDebugging };
	CMFCEditBrowseCtrl mExeEditBrowse; 

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
private:
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	
	Free_Dll_Dialog FreeDll;
	PRO_TEXT_Dialog Pro_Text;
	HS_DATA_DIALOG DataHs;

	DWORD FileSize;
	DWORD FoaEP;
	DWORD AfterRVAData;
	DWORD AddrEP;
	DWORD AfterEP;
	DWORD StartTextShellCode;
	DWORD ImageBase;

	DWORD SectionNum;
	//TLS变量
	DWORD FileSizeAdd=0;

	DWORD TextTLSAddr;

	DWORD RVAFileSize;
public:
	afx_msg void OnBnClickedButton1();
	//SEH反调试
	DWORD FindEmptyCode();
	DWORD FindEmptyDataAndAddData();
	void ModefyAllShellCode();
	DWORD WriterToPEFileAndDisk(char* name);
	//TLS反调试
	afx_msg void OnBnClickedButton6();
	void TLSModefyMem(char* path);
	LPVOID AntiPEFileToMemory(LPSTR lpszFile, int Add);
};
