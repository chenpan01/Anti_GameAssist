
// Anti_WaiGuaDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "Anti_WaiGua.h"
#include "Anti_WaiGuaDlg.h"
#include "afxdialogex.h"
#include "HS_DATA_DIALOG.h"
#include "PRO_TEXT_Dialog.h"
#include <Windows.h>
#include<sstream>
#include<iostream>
#include<string>
#include<cstring>
#include<stack>
#include<cstdlib>
#include<cstdio>
#include <io.h>  
#include <fcntl.h> 
#include "Free_Dll_Dialog.h"
#include "Anti_Debugg_Dialog.h"
#include "ToolAndOpenMore.h"
using namespace std;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CAnti_WaiGuaDlg 对话框



CAnti_WaiGuaDlg::CAnti_WaiGuaDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CAnti_WaiGuaDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAnti_WaiGuaDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB1, m_tab);
}

BEGIN_MESSAGE_MAP(CAnti_WaiGuaDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
END_MESSAGE_MAP()


// CAnti_WaiGuaDlg 消息处理程序

BOOL CAnti_WaiGuaDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	//添加控件台资源，调式使用
	/*
	::AllocConsole();
	FILE *fp;
	freopen_s(&fp, "CONOUT$", "w+t", stdout);//申请写，这个是针对VS2013版本的代码，在VS较为早期的版本比
	*/

	// TODO:  在此添加额外的初始化代码 
	m_tab.AddPage(TEXT("call及数据保护"), &HS_DATA, IDD_DIALOG_HS_DATA);  
	m_tab.AddPage(TEXT("代码检测"), &Pro_Code, IDD_DIALOG_Pro_Code); 
	m_tab.AddPage(TEXT("HOOK检测"), &Free_Dll, IDD_DIALOG_FreeDll);
	m_tab.AddPage(TEXT("调式工具检测和多开检测"), &TAOM, IDD_DIALOG_ToolAndOpenMore);
	m_tab.AddPage(TEXT("添加反调试"), &AntiDebug, IDD_DIALOG_AntiDebugging);

	m_tab.Show();
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAnti_WaiGuaDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAnti_WaiGuaDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAnti_WaiGuaDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

