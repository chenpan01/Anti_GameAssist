// PRO_TEXT_Dialog.cpp : 实现文件
//

#include "stdafx.h"
#include "Anti_WaiGua.h"
#include "PRO_TEXT_Dialog.h"
#include "HS_DATA_DIALOG.h"
#include "afxdialogex.h"
#include "md5.h"
#include <string>
#include <iostream>
#include <TlHelp32.h>
#include <AtlConv.h>
#include <fstream>
#include <windows.h>
#include<thread>
using namespace std;
// PRO_TEXT_Dialog 对话框
#define SZLen 0x400
IMPLEMENT_DYNAMIC(PRO_TEXT_Dialog, CDialogEx)
//变量声明
DWORD pid;
DWORD AddrFuncSZ[SZLEN];
BYTE AddrFunOrignal[SZLEN];
BYTE g_chINT3 = 0xCC;
CHAR szLogFilePath[SZLEN];
HS_DATA_DIALOG DataHs;
//函数声明
BOOL SetUserFunc(LPDEBUG_EVENT pde);
DWORD WINAPI DebugLoop(LPVOID pid);
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde);

CREATE_PROCESS_DEBUG_INFO g_cpdi;
PRO_TEXT_Dialog::PRO_TEXT_Dialog(CWnd* pParent /*=NULL*/)
	: CDialogEx(PRO_TEXT_Dialog::IDD, pParent)
{

}

PRO_TEXT_Dialog::~PRO_TEXT_Dialog()
{
}

void PRO_TEXT_Dialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, mExeEditBrowse);
	DDX_Control(pDX, IDC_MFCEDITBROWSE2, mExeEditBrowse_Ver);
	DDX_Control(pDX, IDC_LIST5, mProList);
}


BEGIN_MESSAGE_MAP(PRO_TEXT_Dialog, CDialogEx)
	ON_EN_CHANGE(IDC_MFCEDITBROWSE1, &PRO_TEXT_Dialog::OnEnChangeMfceditbrowse1)
	ON_EN_CHANGE(IDC_MFCEDITBROWSE2, &PRO_TEXT_Dialog::OnEnChangeMfceditbrowse2)
	ON_BN_CLICKED(IDC_BUTTON1, &PRO_TEXT_Dialog::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON3, &PRO_TEXT_Dialog::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON2, &PRO_TEXT_Dialog::OnBnClickedButton2)
END_MESSAGE_MAP()
BOOL PRO_TEXT_Dialog::OnInitDialog()
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
	AddProcessToList();
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
BOOL PRO_TEXT_Dialog::GetImportFilePathAndUserFunc(char* path)
{
	char* DiskPath = (char*)malloc(SZLen);
	PVOID PeBuffer = DataHs.PEFileToMemory(path); 
	DiskPath = "d:\\text.bin";
	//初始化函数头部数组
	memset(AddrFuncSZ,-1,SZLEN);
	//定义必要的变量
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD SectionNum = 0;

	if (PeBuffer == NULL)
	{
		printf("(GetImportFilePath)PE buffer为空\n");
		return 0;
	}

	if (*((PWORD)PeBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(GetImportFilePath)不是有效的EXE文件\n");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)PeBuffer;

	if (*((PWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(GetImportFilePath)不是有效的PE文件\n");
		return 0;
	}
	//PE文件头对象
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 0x4);
	//PE可选头对象 PIMAGE_OPTIONAL_HEADER32 pOptionHeader
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	//获取头节表结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	ImageBase = pOptionHeader->ImageBase;
	TextStartAddr = pSectionHeader->PointerToRawData;
	TextEndAddr = (pSectionHeader + 1)->PointerToRawData;
	//计算OEP
	DWORD OEP = pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase;
	//获取PE文件中函数的地址
	ImageBase = pOptionHeader->ImageBase;
	int Funi = 0;
	//寻找函数位置
	for (DWORD i = TextStartAddr; i < TextStartAddr + pSectionHeader->SizeOfRawData; i++)
	{
		//获取函数头部信息
		pFuncHeader = (_FuncHeader*)((DWORD)PeBuffer + i);
		//判断是否为函数头部
		if (pFuncHeader->p1 == 0x55 && pFuncHeader->p2 == 0x89 && pFuncHeader->p3 == 0xE5 || pFuncHeader->p1 == 0x53 && pFuncHeader->p2 == 0x56 && pFuncHeader->p3 == 0x57 && pFuncHeader->p4 == 0x55 || pFuncHeader->p1 == 0x55 && pFuncHeader->p2 == 0x8B && pFuncHeader->p3 == 0xEC)
		{
			//把FOA地址转换成VA
			DWORD FuncAddr = DataHs.FoaToRva(PeBuffer, i) + ImageBase;
			if (FuncAddr>OEP)
			{
				AddrFuncSZ[Funi++] = FuncAddr;
			}
		}

	}
	//把代码段信息写入到磁盘文件中
	std::ofstream outFile;
	
	//打开文件
	outFile.open(DiskPath);
	for (int i = TextStartAddr; i < TextEndAddr; i++)
	{
		BYTE* context = (BYTE*)((DWORD)pPEHeader+i);
		//写入数据
		outFile << *context;
	}
	//把FOA地址转换成RVA
	TextStartAddr = DataHs.FoaToRva(PeBuffer, TextStartAddr);
	TextStartAddr = DataHs.FoaToRva(PeBuffer, TextEndAddr);
	//关闭文件
	outFile.close();
	MD5 md5(ifstream(DiskPath, ios::binary));
	ProCheckV=md5.toString();
	if (remove(DiskPath) != 0)
		return FALSE;
	return TRUE;
}
// PRO_TEXT_Dialog 消息处理程序
void PRO_TEXT_Dialog::OnEnChangeMfceditbrowse1()
{
	//得到程序路径
	mExeEditBrowse.GetWindowText(ExePath);
	CStringA tmp = ExePath;
	char* pp = tmp.GetBuffer();
	//获取导出到磁盘中的文件路径
	MD5 md5(ifstream(pp, ios::binary));
	//计算静态校验值
	CheckValue = md5.toString();
	//计算动态校验值
	GetImportFilePathAndUserFunc(pp);
	return ;
}
int PRO_TEXT_Dialog::GerGangPos(char* pp)
{
	for (int i = strlen(pp) - 1; i > -1; i--)
	{
		if (pp[i] == '\\')
		{
			return i;
			break;
		}
	}
	return -1;
}
BOOL PRO_TEXT_Dialog::IsNameEqual(CString Path1, CString Path2, char pos)
{
	CStringA tmp = Path2;    
	char* pp = tmp.GetBuffer();
	//判断进程是否相等
	int IsEqual = 1;
	//反向查找
	int GangXb1 = Path1.ReverseFind('\\');
	int GangXb2 = Path2.ReverseFind(pos);
	//名字的长度不等
	if (Path1.GetLength() - GangXb1 != Path2.GetLength() - GangXb2)
		IsEqual = 0;
	else
		for (int i = GangXb1 + 1, j = GangXb2 + 1; i < Path1.GetLength() && j < Path2.GetLength(); i++, j++)
		{
			if (Path1.GetAt(i) != Path2.GetAt(j))
			{
				IsEqual = 0;
				break;
			}
		}
	return IsEqual;
}
void PRO_TEXT_Dialog::OnEnChangeMfceditbrowse2()
{
	//获取文件路径
	mExeEditBrowse_Ver.GetWindowText(ExePath_Ver);
	int ans=IsNameEqual(ExePath_Ver, ExePath,'\\');

	//选择的进程名，有误
	if (ans == 0)
	{
		::MessageBoxA(0, "选择的文件名有误", "温馨提示", 0);
		return;
	}
	//确定文件后，计算校验值，比较是否相等
	CStringA tmpCS = ExePath_Ver;
	char* pp2 = tmpCS.GetBuffer();
	MD5 md5(ifstream(pp2, ios::binary));
	string CheckValue1 = md5.toString();
	if (CheckValue != CheckValue1 )
	{
		::MessageBoxA(0, "文件代码段已被修改", "温馨提示", 0);
	}
	else
	{
		::MessageBoxA(0, "文件代码段没有被修改", "温馨提示", 0);
	}
	return;
}
//往列表中添加进程信息
void PRO_TEXT_Dialog::AddProcessToList()
{
	SYSTEM_INFO sysInfo;
	GetNativeSystemInfo(&sysInfo);

	DWORD dwPid = 0;
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return;

	Process32First(hProcessSnap, &pe32);
	do
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		BOOL isWow64;
		if (IsWow64Process(hProcess, &isWow64))
		{
			TCHAR szBuf[1024] = { 0 };
			if (isWow64 || sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			{
				wsprintf(szBuf, _T("%s %4d %s"), _T("(32位)"), pe32.th32ProcessID, pe32.szExeFile);
			}
			else
			{
				wsprintf(szBuf, _T("%s %4d %s"), _T("(64位)"), pe32.th32ProcessID, pe32.szExeFile);
			}
			//返回列表中的索引  
			int count = mProList.AddString(szBuf);
			//对索引项设值
			mProList.SetItemData(count, pe32.th32ProcessID);
		}
		CloseHandle(hProcess);
	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return;
}
//刷新进程
void PRO_TEXT_Dialog::OnBnClickedButton1()
{
	// TODO:  在此添加控件通知处理程序代码
	mProList.ResetContent();
	AddProcessToList();
}
//执行校验
void PRO_TEXT_Dialog::OnBnClickedButton3()
{
	char* DiskPath = "c:\\ProInfo.bin";
	// TODO:  在此添加控件通知处理程序代码
	if (mProList.GetCurSel() == -1)
	{
		::MessageBoxA(0,"请选择进程","温馨提示",0);
		return;
	}
	if (CheckValue.length() == 0 || ExePath.GetLength() == 0)
	{
		::MessageBoxA(0, "没有选择校验文件", "温馨提示", 0);
		return;
	}
	DWORD pid = mProList.GetItemData(mProList.GetCurSel());
	//判断进程名是否跟PE文件名相同
	CString str;
	mProList.GetText(mProList.GetCurSel(), str);
	int ans1=IsNameEqual(ExePath,str,' ');
	if (!ans1)
	{
		::MessageBoxA(0, "没有选择正确的进程", "温馨提示", 0);
		return;
	}
	//把代码段信息写入到磁盘文件中
	std::ofstream outFile;
	//打开文件
	outFile.open(DiskPath);
	HANDLE hProcess;
    BYTE tmp;
    DWORD dwNumberOfBytesRead;
	//pid为目标进程的id
	hProcess = OpenProcess(PROCESS_VM_READ, false, pid); 
	//printf("TextStartAddr:%x   TextEndAddr:%x\n", TextStartAddr + ImageBase, TextEndAddr + ImageBase);
	//遍历内存中的代码段
	for (DWORD i = TextStartAddr + ImageBase; i < TextEndAddr + ImageBase; i++)
	{
		ReadProcessMemory(hProcess, (LPCVOID)i, &tmp, sizeof(BYTE), NULL);
		//写入数据
		outFile << tmp;
	}
	//关闭文件
	outFile.close();
	MD5 md5;
	string ans = MD5(ifstream(DiskPath, ios::binary)).toString();
	if (ans == ProCheckV)
		::MessageBoxA(0,"文件内存未修改","温馨提示",0);
	else
	{
		::MessageBoxA(0, "文件内存已修改", "温馨提示", 0);
	}
	if (!remove(DiskPath))
		printf("OnBnClickedButton3 移除失败\n");
	else
		printf("OnBnClickedButton3 移除成功\n");
	return ;
}

//导出日志文件
void PRO_TEXT_Dialog::OnBnClickedButton2()
{
	//判断有无选择PE文件和进程
	if (CheckValue.length() == 0 || ExePath.GetLength() == 0)
	{
		::MessageBoxA(0, "没有选择校验文件", "温馨提示", 0);
		return;
	}
	if (mProList.GetCurSel() == -1)
	{
		::MessageBoxA(0, "请选择进程", "温馨提示", 0);
		return;
	}
	//判断选择的进程是否正确
	CString str;
	mProList.GetText(mProList.GetCurSel(), str);
	int ans1 = IsNameEqual(ExePath, str, ' ');
	if (!ans1)
	{
		::MessageBoxA(0, "没有选择正确的进程", "温馨提示", 0);
		return;
	}
	memset(szLogFilePath, '\0', SZLEN);
	GetModuleFileName(NULL, szLogFilePath, MAX_PATH);
	// 删除文件名，只获得路径字串
	(_tcsrchr(szLogFilePath, _T('\\')))[1] = 0;
	char* p = "\log.txt";
	int i,j;
	//拼接文件名
	for (i = strlen(szLogFilePath), j = 0; j < strlen(p); j++,i++)
	{
		szLogFilePath[i] = p[j];
	}
	szLogFilePath[i] = '\0';
	
    pid = mProList.GetItemData(mProList.GetCurSel());
	//创建线程，传入参数
	HANDLE hThread1 = CreateThread(NULL, 0, DebugLoop, NULL, 0, NULL);

	CloseHandle(hThread1);
}

DWORD WINAPI DebugLoop(LPVOID a)
{
	DEBUG_EVENT de;
	DWORD dwContinueStatus;
	if (!DebugActiveProcess(pid))
	{
		printf("DebugActiveProcess(%d) failed!!!"
			"Error Code = %d\n", pid, GetLastError());
		return 0;
	}
	//等待调式事件
	while (WaitForDebugEvent(&de, INFINITE))
	{
		LPDEBUG_EVENT pde = &de;
		PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;
		dwContinueStatus = DBG_CONTINUE;

		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			SetUserFunc(&de);
		}
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)
		{
			printf("EXCEPTION_DEBUG_EVENT \n");
			if (OnExceptionDebugEvent(&de))
				continue;
		}
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)
		{
			break;
		}
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
	return 0;
}

BOOL SetUserFunc(LPDEBUG_EVENT pde)
{
	printf("SetUserFunc\n");
	memset(AddrFunOrignal,-1,SZLEN);
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
	for (int i = 0; AddrFuncSZ[i] != -1; i++)
	{
		if (!::ReadProcessMemory(g_cpdi.hProcess, (LPVOID)AddrFuncSZ[i], &AddrFunOrignal[i], sizeof(BYTE), NULL))
			printf("ReadProcessMemory is fail\n");
		else
			printf("AddrFunOrignal[i] is %x\n", AddrFunOrignal[i]);
		if (!::WriteProcessMemory(g_cpdi.hProcess, (LPVOID)AddrFuncSZ[i], &g_chINT3, sizeof(BYTE), NULL))
			printf("WriteProcessMemory is fail\n");
	}
	return TRUE;
}
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
	CONTEXT ctx;
	PBYTE lpBuffer = NULL;
	DWORD dwNumOfBytesToWrite, dwAddrOfBuffer;
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;
	FILE* dst = fopen(szLogFilePath, "ab+");
	if (dst != NULL)
		::MessageBoxA(0, "日志文件已生成", "消息", 1);
	// BreakPoint exception (INT 3)
	if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
	{
		DWORD ExAddress=(DWORD)(per->ExceptionAddress);
		for (int i = 0; AddrFuncSZ[i] != -1 ; i++)
		{
			//加个输出
			//printf("AddrFuncSZ[i]:%x (DWORD)(per->ExceptionAddress): %x\n", AddrFuncSZ[i], ExAddress);
			if (AddrFuncSZ[i] == ExAddress)
				{
					//写回原先内容
					WriteProcessMemory(g_cpdi.hProcess,&AddrFuncSZ[i],&AddrFunOrignal[i],sizeof(BYTE),NULL);
					// 获取Thread Context
					ctx.ContextFlags = CONTEXT_CONTROL;
					GetThreadContext(g_cpdi.hThread, &ctx);
					//获取线程上下文信息
					CString str;
					str.Format("执行函数为：sub_%x,其中EAX为：%x、EBX为：%x、ECX为：%x、EDX为：%x、EIP为：%x、ESP为：%x、EBP为：%x、EDI为：%x、ESI为：%x\n", AddrFuncSZ[i],ctx.Eax,ctx.Ebx,ctx.Ecx,ctx.Edx,ctx.Eip,ctx.Esp,ctx.Ebp,ctx.Edi,ctx.Esi);
					CStringA tmp = str;
					char* context = tmp.GetBuffer();
					fwrite(context, sizeof(context[0]), strlen(context), dst);
					//重新设置上下文
					ctx.Eip = AddrFuncSZ[i];
					SetThreadContext(g_cpdi.hThread, &ctx);
					//继续调式
					ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
					Sleep(0);
					//重新设置断点
					WriteProcessMemory(g_cpdi.hProcess,&AddrFuncSZ[i],&g_chINT3,sizeof(BYTE),NULL);
					return TRUE;
				}
		}
	}
	return FALSE;
}
