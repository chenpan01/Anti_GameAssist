// ToolAndOpenMore.cpp : 实现文件
//
#include "stdafx.h"
#include "Anti_WaiGua.h"
#include "ToolAndOpenMore.h"
#include "afxdialogex.h"
#include "Free_Dll_Dialog.h"
#include "PRO_TEXT_Dialog.h"
#include <TlHelp32.h>
#include "HS_DATA_DIALOG.h"
#include<cstdio>
#include<windows.h>
#include <list>
#include <vector>
#include <windows.h>
#include <iostream>
using namespace std;
// ToolAndOpenMore 对话框
BYTE g_chINT32 = 0xCC;
BYTE g_Orignal;
LPVOID g_pCreateMutex = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi2;
int NameNum=0;
string Name[SZLEN];
int IsOpenMore;

typedef struct AllWindowsTitle
{
	DWORD pid;
	vector<HWND> *HWNDPid;
}EnumHWndsArg, *LPEnumHWndsArg;
//函数声明
void OnStartDebug(LPDEBUG_EVENT pde);
DWORD OnDealException(LPDEBUG_EVENT pde);
DWORD WINAPI DebugLoop2(LPVOID pid);
BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam);
IMPLEMENT_DYNAMIC(ToolAndOpenMore, CDialogEx)
ToolAndOpenMore::ToolAndOpenMore(CWnd* pParent /*=NULL*/)
	: CDialogEx(ToolAndOpenMore::IDD, pParent)
{

}

BOOL ToolAndOpenMore::OnInitDialog()
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
	FreeDll.AddProcessToList(mProList);
	//只能打开exe文件
	mExeFilePath.EnableFileBrowseButton(NULL, _T("Exe Files (*.exe)|*.exe|All Files (*.*)|*.*||"));
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
ToolAndOpenMore::~ToolAndOpenMore()
{

}

void ToolAndOpenMore::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, mExeFilePath);
	DDX_Control(pDX, IDC_LIST1, mProList);
}


BEGIN_MESSAGE_MAP(ToolAndOpenMore, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON6, &ToolAndOpenMore::OnBnClickedButton6)
	ON_BN_CLICKED(IDC_BUTTON1, &ToolAndOpenMore::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &ToolAndOpenMore::OnBnClickedButton2)
END_MESSAGE_MAP()
BOOL ToolAndOpenMore::TraverseAllPro(DWORD pid)
{
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	//进程快照 申明获取数据类型
	HANDLE hProSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if (hProSnap == INVALID_HANDLE_VALUE)
	{
		return TRUE;
	}
	//循环遍历
	for (Process32First(hProSnap, &pe); Process32Next(hProSnap, &pe);)
	{
		if (pe.th32ProcessID == pid)
			continue;
		//如果工具过大
		if (FindOpenMoreByCode(pe.th32ProcessID, 1) == 2)
			continue;
		else if (FindOpenMoreByCode(pe.th32ProcessID, 1)==0)
		{
			return FALSE;
		}
	}
	//关掉句柄
	CloseHandle(hProSnap);
	return TRUE;
}
//使用特征码找到Duokai
DWORD ToolAndOpenMore::FindOpenMoreByCode(DWORD pid,int n)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//获取进程基质
	//把进程内存加载到字符数组中
	unsigned char ProMem[MaxLenSz];
	FreeDll.GetProMemToChar(pid, ProMem);
	if (ProMem[0]==0xFF)
	{
		return 2;
	}
	//记录code段的部分代码
	//PE文件头
	pDosHeader = (PIMAGE_DOS_HEADER)ProMem;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew+0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD EP = pOptionHeader->AddressOfEntryPoint;
	//代码段
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);
	//存储特征码
	int i = 0;
	int j = EP;
	for (; i < MaxLenSz && i < pSectionHeader->SizeOfRawData && n == 0; i++, j++)
	{
		TextCode[i] = *((PBYTE)ProMem + j);
	}
	//遍历其它进程发现是否有相同特征码
	i = 0;
    j = EP;
	for (; i < MaxLenSz && i < pSectionHeader->SizeOfRawData && n; i++, j++)
	{
		if (TextCode[i] != *((PBYTE)ProMem + j))
		{
			return 1;
		}
	}
	return 0;
}
//使用名字找到Duokai
BOOL ToolAndOpenMore::FindOpenMoreByName(DWORD pid)
{
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);
	HANDLE hPro = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	string Name;
	//获取pid对应的进程名
	for (Process32First(hPro, &pe); Process32Next(hPro, &pe);)
	{
		if (pe.th32ProcessID == pid)
		{
			Name = pe.szExeFile;
			break;
		}
	}
	//比较其他进程名
	for (Process32First(hPro, &pe); Process32Next(hPro, &pe);)
	{
		if (pe.th32ProcessID != pid)
		{
			if (!strcmp(Name.c_str(), pe.szExeFile))
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}
//回调函数定义方式
BOOL CALLBACK lpEnumFunc(HWND hwnd, LPARAM lParam)
{
	LPEnumHWndsArg Win = (LPEnumHWndsArg)lParam;
	DWORD Pid;
	GetWindowThreadProcessId(hwnd,&Pid);
	if (Pid == Win->pid)
	{
		Win->HWNDPid->push_back(hwnd);
	}
	return TRUE;
}
void ToolAndOpenMore::GetHWndsByProcessID(DWORD processID, std::vector<HWND> &vecHWnds)
{
	EnumHWndsArg wi;
	wi.pid = processID;
	wi.HWNDPid = &vecHWnds;
	EnumWindows(lpEnumFunc, (LPARAM)&wi);
}
//使用窗口名找到Duokai
BOOL ToolAndOpenMore::FindOpenMoreByWinName(DWORD pid)
{
	vector<HWND> vecHWnds;
	GetHWndsByProcessID(pid,vecHWnds);
	for (int i = 0; i<2; i++) //vecHWnds.size()
	{
		char a[SZLEN];
		::GetWindowTextA((HWND)vecHWnds[i], a, SZLEN);
		CWnd * m_pWnd = FindWindow(NULL, a);
		DWORD Pid;
		GetWindowThreadProcessId(m_pWnd->m_hWnd, &Pid);
		if (Pid!=pid)
		{
			return TRUE;
		}
	}
	return FALSE;
}

void OnStartDebug(LPDEBUG_EVENT pde)
{
	//获取CreateMutex地址
	g_pCreateMutex = GetProcAddress(GetModuleHandleA("kernel32.dll"),"CreateMutex");
	//对头部进行修改
	memcpy(&g_cpdi2,&pde->u.CreateProcessInfo,sizeof(CREATE_PROCESS_DEBUG_INFO));
	ReadProcessMemory(g_cpdi2.hProcess,g_pCreateMutex,&g_Orignal,sizeof(BYTE),NULL);
	WriteProcessMemory(g_cpdi2.hProcess,g_pCreateMutex,&g_chINT32,sizeof(BYTE),NULL);
	return;
}
DWORD OnDealException(LPDEBUG_EVENT pde)
{
	CONTEXT ctx;
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;
	DWORD EspContent;
	//判断是否是函数发生异常
	if (per->ExceptionAddress == g_pCreateMutex && pde->dwDebugEventCode == EXCEPTION_BREAKPOINT)
	{
		//解除HOOK 恢复原值
		WriteProcessMemory(&pde->dwProcessId, g_pCreateMutex,&g_Orignal,sizeof(BYTE),NULL);
		//获取线程上下文
		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(g_cpdi2.hThread,&ctx);
		//得到ESP+8的值
		ReadProcessMemory(g_cpdi2.hProcess, LPVOID(ctx.Esp + 0x8), &EspContent, sizeof(DWORD), NULL);
		//取出地址并获取字符串
		Name[NameNum++] = (char*)(EspContent);
		//判断有无重负互斥名
		list<string> list1;
		for (int i = 0; i < NameNum; i++)
		{
			list1.push_back(Name[i]);
		}
		int len1 = list1.size();
		list1.unique();
		int len2 = list1.size();
		//判断是否有重负元素
		if (len1 != len2)
		{
			//::MessageBox(0,"检测出程序多开","温馨提示",0);
			IsOpenMore = 1;
			return -1;
		}
		//让EIP为当前地址
		ctx.Eip = (DWORD)g_pCreateMutex;
		//设置线程上下文
		SetThreadContext(g_cpdi2.hThread, &ctx);
		//继续调式
		ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
		//修改头部
		Sleep(0);
		WriteProcessMemory(g_cpdi2.hProcess, g_pCreateMutex, &g_chINT32, sizeof(BYTE), NULL);
		return 1;
	}
	return 0;
}
//多开检测
void ToolAndOpenMore::OnBnClickedButton6()
{
	IsOpenMore = 0;
	// TODO:  在此添加控件通知处理程序代码
	DWORD index = mProList.GetCurSel();
	if (index == -1)
	{
		::MessageBoxA(0, "请选择进程", "温馨提示", 1);
		return;
	}
	//获取进程pid
	DWORD dwPid = mProList.GetItemData(index);
	if (!FindOpenMoreByCode(dwPid, 0) && !TraverseAllPro(dwPid))
	{
		::MessageBox(0, "检测出程序多开", "温馨提示", 0);
		return ;
	}
	//检测双开
	if (FindOpenMoreByWinName(dwPid) || FindOpenMoreByName(dwPid))
	{
		::MessageBox(0, "检测出程序多开", "温馨提示", 0);
		return;
	}
	else
	{
		//调式程序
		if (!DebugActiveProcess(dwPid))
		{
			printf("DebugActiveProcess(%d) failed!!!\n"
				"Error Code = %d\n", dwPid, GetLastError());
		}
		//创建线程执行调式
		HANDLE hThread1 = CreateThread(NULL, 0, DebugLoop2, NULL, 0, NULL);
		CloseHandle(hThread1);
	}
	if (!IsOpenMore)
	{
		::MessageBox(0,"没有检测出多开","温馨提示",0);
	}
	return;
}
//调式函数
DWORD WINAPI DebugLoop2(LPVOID pid)
{
	DEBUG_EVENT de;
	DWORD dwContinueStatus;
	while (WaitForDebugEvent(&de, -1))
	{
		dwContinueStatus = DBG_CONTINUE;
		if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
		{
			OnStartDebug(&de);
		}
		else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			if (OnDealException(&de) == 1)
				continue;
			else if (OnDealException(&de) == -1)
				return 0;
		}
		else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			return 0;
		}
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);

	}
	return 1;
}
//获取工具特征码函数 PEFileToMemory
void ToolAndOpenMore::GetToolCode(BYTE* ToolCode, CString strPath)
{
    PeBuffer = (PVOID)DataHs.PEFileToMemory(DataHs.CStringToCharSz(strPath));
	//定位到代码段
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL, tpSectionHeader;
	if (PeBuffer == NULL)
	{
		printf("(GetToolCode)PE buffer为空\n");
		return ;
	}
	if (*((PWORD)(PeBuffer)) != IMAGE_DOS_SIGNATURE)
	{
		printf("(GetToolCode)不是有效的EXE文件\n");
		return ;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)PeBuffer;

	if (*((PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(GetToolCode)不是有效的PE文件\n");
		return ;
	}
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)PeBuffer + pDosHeader->e_lfanew + 0x4);
	DWORD SectionNum = pPEHeader->NumberOfSections;
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD EP = pOptionHeader->AddressOfEntryPoint;
	RVAToolEp = EP;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	tpSectionHeader = pSectionHeader;
	int j = 0;
	for (int i = tpSectionHeader->PointerToRawData; i < tpSectionHeader->PointerToRawData + tpSectionHeader->SizeOfRawData && j<SZLEN; i++)
	{
		if (DataHs.FoaToRva(PeBuffer, i) < EP)
			continue;
		ToolCode[j++] = *((BYTE*)((DWORD)PeBuffer + i));
	}
	return;
}
DWORD ToolAndOpenMore::GetProCodeToSZ(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);//获取进程句柄
	PBYTE ExeProBase = FreeDll.GetExeBase(pid);
	if (ExeProBase == NULL)
	{
		return 0;
	}
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ExeProBase;
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 0x4);
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	DWORD SectionAligment = pOptionHeader->SectionAlignment;
	int i;
	for (i = 0; i < MaxLenSz; i++)
	{
		ReadProcessMemory(hProcess, (ExeProBase + i), &ProMem[i], sizeof(char), NULL);
	}
	return 1;
}
//判断工具是否在运行，是否是保护进程的PPID
BOOL ToolAndOpenMore::ToolIsRunning(DWORD pid,BYTE* ToolCode)
{
	//遍历所有进程，获取PID
	int len = mProList.GetCount();
	CString con;
	for (int i = 0; i < len; i++)
	{
		mProList.GetText(i, con);
		memset(ProMem, 0, MaxLenSz);
		if (!GetProCodeToSZ(mProList.GetItemData(i)))
			continue;
		//PE文件头
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ProMem;
		PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 0x4);
		PIMAGE_OPTIONAL_HEADER32 pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
		DWORD EP = pOptionHeader->AddressOfEntryPoint;
		//判断EP是不是被保护了
		if (EP> 0x2000)
			EP = RVAToolEp;
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);;
		PIMAGE_SECTION_HEADER tpSectionHeader = pSectionHeader;
		int ii = 0;
		for (int j = EP; ii < SZLEN && j < tpSectionHeader->VirtualAddress + tpSectionHeader->SizeOfRawData; j++, ii++)
		{
			BYTE con = *((BYTE*)((DWORD)pDosHeader+j));
			if (ToolCode[ii] != con)
			{
				break;
			}
		}
		//找到调式工具
		if (ii == SZLEN)
		{
			if (isToolSon(mProList.GetItemData(i), pid))
				return TRUE;
		}
	}
	return FALSE;
}
BOOL ToolAndOpenMore::isToolSon(DWORD father, DWORD son)
{
	HANDLE hSnapPro = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	PROCESSENTRY32 pe;
	for (Process32First(hSnapPro, &pe); Process32Next(hSnapPro, &pe);)
	{
		if (pe.th32ProcessID == son && pe.th32ParentProcessID == father)
		{
			return TRUE;
		}
	}
	return FALSE;
}
//工具检测
void ToolAndOpenMore::OnBnClickedButton1()
{
	// TODO:  在此添加控件通知处理程序代码
	CString ProPath;
	mExeFilePath.GetWindowText(ProPath);
	if (ProPath.GetLength() == 0)
	{
		::MessageBox(0, "请选择调式工具", "温馨提示", 0);
		return;
	}
	DWORD index = mProList.GetCurSel();
	if (index == -1)
	{
		::MessageBoxA(0, "请选择要保护的进程", "温馨提示", 0);
		return;
	}
	BYTE TextCode[SZLEN];
	memset(TextCode,0,SZLEN);
	GetToolCode(TextCode, ProPath);
	DWORD pid = mProList.GetItemData(index);
	//保护进程ID
	if (ToolIsRunning(pid, TextCode))
	{
		::MessageBoxA(0, "检测到调式工具正在调式保护进程", "温馨提示", 0);
	}
	else
	{
		::MessageBoxA(0, "没有检测到调式工具正在调式保护进程", "温馨提示", 0);
	}
	return;
}
//刷新进程
void ToolAndOpenMore::OnBnClickedButton2()
{
	// TODO:  在此添加控件通知处理程序代码
	mProList.ResetContent();
	FreeDll.AddProcessToList(mProList);
	return;
}
