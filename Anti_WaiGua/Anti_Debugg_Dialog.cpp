// Anti_Debugg_Dialog.cpp : 实现文件
//

#include "stdafx.h"
#include "Anti_WaiGua.h"
#include "Anti_Debugg_Dialog.h"
#include "afxdialogex.h"
#include "Anti_WaiGua.h"
#include "ToolAndOpenMore.h"
#include "afxdialogex.h"
#include "Free_Dll_Dialog.h"
#include "PRO_TEXT_Dialog.h"
#include <TlHelp32.h>
#include "HS_DATA_DIALOG.h"
#include <fstream>
#include <iostream>  
using namespace std;
unsigned char ShellCode[118] = { 0x68, 0xb8, 0x10, 0x40, 0x00, 0x64, 0xFF, 0x35, 0x00, 0x00, 0x00, 0x00, 0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x33, 0xC0, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x90
, 0x00, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x68, 0x20, 0x30, 0x40, 0x00, 0x6A, 0x00, 0xE8, 0xC2, 0xFF, 0xFF, 0xFF, 0x64, 0x8F, 0x05, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x04, 0x6A, 0x00, 0xE8, 0xB7
, 0xFF, 0xFF, 0xFF, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x8B, 0x74, 0x24, 0x0C
, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x80, 0x78, 0x02, 0x01, 0x75, 0x0C, 0xC7, 0x86, 0xB8, 0x00
, 0x00, 0x00, 0x8E, 0x10, 0x40, 0x00, 0xEB, 0x0A, 0xC7, 0x86, 0xB8, 0x00, 0x00, 0x00, 0x20, 0x10
, 0x40, 0x00, 0x33, 0xC0, 0xC3, 0 };
unsigned char TLSCode[0x32] = { 0x83, 0x7C, 0x24, 0x08, 0x01, 0x75, 0x28, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x80, 0x78, 0x02
, 0x00, 0x74, 0x1C, 0x6A, 0x00, 0x68, 0x70, 0xC2, 0x40, 0x00, 0x68, 0x80, 0xC2, 0x40, 0x00, 0x6A
, 0x00, 0xFF, 0x15, 0xE8, 0x80, 0x40, 0x00, 0x6A, 0x01, 0xFF, 0x15, 0x28, 0x80, 0x40, 0x00, 0xC2
, 0x0C, 0x00 };

IMPLEMENT_DYNAMIC(Anti_Debugg_Dialog, CDialogEx)

Anti_Debugg_Dialog::Anti_Debugg_Dialog(CWnd* pParent /*=NULL*/)
	: CDialogEx(Anti_Debugg_Dialog::IDD, pParent)
{

}

Anti_Debugg_Dialog::~Anti_Debugg_Dialog()
{
}
BOOL Anti_Debugg_Dialog::OnInitDialog()
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
	//只能打开exe文件
	mExeEditBrowse.EnableFileBrowseButton(NULL, _T("Exe Files (*.exe)|*.exe|All Files (*.*)|*.*||"));
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
void Anti_Debugg_Dialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, mExeEditBrowse);
}


BEGIN_MESSAGE_MAP(Anti_Debugg_Dialog, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &Anti_Debugg_Dialog::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON6, &Anti_Debugg_Dialog::OnBnClickedButton6)
END_MESSAGE_MAP()


//搜索代码段空白代码
DWORD Anti_Debugg_Dialog::FindEmptyCode()
{
	//把exe文件加载进内存
	//读取PE文件相关的变量
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	ImageBase = pOptionHeader->ImageBase;
	AddrEP = pOptionHeader->AddressOfEntryPoint;
	SectionNum = pPEHeader->NumberOfSections;
	RVAFileSize = pOptionHeader->SizeOfImage;
	//定位到代码段结构体
	PIMAGE_SECTION_HEADER tpSectionHeader = pSectionHeader;
	//遍历代码段，找到空白代码区域
	int i, j;
	for (i = tpSectionHeader->PointerToRawData; i < tpSectionHeader->SizeOfRawData + tpSectionHeader->PointerToRawData; i++)
	{
		for (j = 0; j<118; j++)
		{
			if (*((PBYTE)((DWORD)pFileBuffer + i+j)) != 0x0)
			{
				break;
			}
		}
		if (j == 118)
		{
			FoaEP = i;
			StartTextShellCode = DataHs.FoaToRva(pFileBuffer, FoaEP) + ImageBase;
			AfterEP = DataHs.FoaToRva(pFileBuffer, FoaEP);
			return 1;
		}
	}
	//如果在代码段没有找到，合适的空闲内存
	FoaEP = FileSize;
	StartTextShellCode = DataHs.FoaToRva(pFileBuffer, FoaEP) + ImageBase;
	AfterEP = DataHs.FoaToRva(pFileBuffer, FoaEP);
	SectionNum = pPEHeader->NumberOfSections;
	//定位到最后段结构体
	tpSectionHeader = pSectionHeader;
	for (int i = 0; i < SectionNum; i++)
	{
		tpSectionHeader++;
	}
	tpSectionHeader--;
	tpSectionHeader->Characteristics = 0xE0000060;
	tpSectionHeader->SizeOfRawData += pOptionHeader->FileAlignment;
	return 0;
}

//搜索数据段空白数据
DWORD Anti_Debugg_Dialog::FindEmptyDataAndAddData()
{
	char s[] = "Debugging";
	//定位到代码段结构体
	PIMAGE_SECTION_HEADER tpSectionHeader = pSectionHeader;
	int i = 0;
	for (i = 0; i < SectionNum; i++, tpSectionHeader++)
	{
		char name[9] = { 0 };
		memset(name,0,9);
		memcpy(name, tpSectionHeader->Name, 9);
		char t[] = ".data";
		if (!strcmp(t, name))
		{
			break;
		}
	}
	if (i == SectionNum)
	{
		return 0;
	}
	int j = 0;
	PBYTE Con;
	for (i = tpSectionHeader->PointerToRawData; i < tpSectionHeader->SizeOfRawData + tpSectionHeader->PointerToRawData; i++)
	{
		for (j = 0; j < 10; j++)
		{
			if (*((PBYTE)((DWORD)pFileBuffer+j+i)) != 0x0)
				break;
		}
		if (j == 10)
		{
			//Debugging把字符串拷贝到内存中
			Con = (PBYTE)((DWORD)pFileBuffer + i);
			memcpy(Con, s, 10);
			AfterRVAData = DataHs.FoaToRva(pFileBuffer, i) + ImageBase;
			printf("AfterRVAData: %x DataFOA: %x\n", AfterRVAData, i);
			return 1;
		}
	}
	return 0;
}
//修改shellcode函数
void Anti_Debugg_Dialog::ModefyAllShellCode()
{
	//修改AddressOfEntryPoint
	pOptionHeader->AddressOfEntryPoint = AfterEP;

	DWORD MessageBoxAddr = (DWORD)GetProcAddress(GetModuleHandle("USER32.dll"), "MessageBoxA");
	DWORD ExitProcessAddr = (DWORD)GetProcAddress(GetModuleHandle("KERNEL32.dll"), "ExitProcess");
	//MessageBox地址-StartAddr-0x32,,off:0x2E
	MessageBoxAddr = MessageBoxAddr - StartTextShellCode - 0x32;
	*((DWORD*)(ShellCode + 0x2E)) = MessageBoxAddr; 
	//ExitProcess地址-StartAddr-0x43,off:0x3F
	ExitProcessAddr = ExitProcessAddr - StartTextShellCode - 0x43;
	*((DWORD*)(ShellCode + 0x3F)) = ExitProcessAddr; 
	//修改SEH函数：StartAddr + 0x4C, off:0x1
	*((DWORD*)(ShellCode + 0x1)) = StartTextShellCode + 0x4C;

	//修改数据地址  (数据地址,off:0x27)
	*((DWORD*)(ShellCode + 0x27)) = AfterRVAData; 

	//SEH函数入参地方 StartAddr+0x22,off:0x62
	*((DWORD*)(ShellCode + 0x62)) = StartTextShellCode + 0x22; 

	//修改原OEP地址 原OEP,off:0x6E
	*((DWORD*)(ShellCode + 0x6E)) = AddrEP + ImageBase; 
	//把Shellcode写入到内存中
	memcpy(((PBYTE)pFileBuffer+FoaEP),ShellCode,118);
	return;
}
//把内存写入到磁盘中
DWORD Anti_Debugg_Dialog::WriterToPEFileAndDisk(char* name)
{
	char SzExePath[0x100];
	memset(SzExePath,0,0x100);
	GetModuleFileName(NULL, SzExePath, 0x100);
	int Pos=Pro_Text.GerGangPos(SzExePath);
	int i, j;
	for (i = Pos+1, j = 0; j < strlen(name); i++, j++)
	{
		SzExePath[i] = name[j];
	}
	for (j = 0; j < 0x20; j++,i++)
		SzExePath[i] = 0;
	//打开文件
	FILE* fp = fopen(SzExePath, "wb");
	//判断，写入
	if (fp != NULL)
	{
		fwrite(pFileBuffer, FileSize + FileSizeAdd, 1, fp);
	}
	else
	{
		printf("MemoryToFile 文件打开失败\n");
		return 0;
	}
	fclose(fp);
	return 1;
}
LPVOID Anti_Debugg_Dialog::AntiPEFileToMemory(LPSTR lpszFile, int IsAdd)
{
	FILE *pFile = NULL;
	LPVOID pFileBuffer1= NULL;
	pFile = fopen(lpszFile, "rb");
	if (!pFile)
	{
		::MessageBoxA(0, "无法打开 EXE 文件!", "", 1);
		return 0;
	}
	//读取文件大小
	fseek(pFile, 0, SEEK_END);
	FileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);
	//分配缓冲区
	pFileBuffer1 = malloc(FileSize);
	if (!pFileBuffer1)
	{
		::MessageBoxA(0, "分配空间失败!", "", 1);
		fclose(pFile);
		return NULL;
	}
	//将文件数据读取到缓冲区
	size_t n = fread(pFileBuffer1, FileSize, 1, pFile);
	if (IsAdd && n)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer1;
		PIMAGE_OPTIONAL_HEADER32 pOPTIONALHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileBuffer1 + pDosHeader->e_lfanew + 0x4 + IMAGE_SIZEOF_FILE_HEADER);
		FileSizeAdd = pOPTIONALHeader->FileAlignment;
		pFileBuffer = malloc(FileSize + FileSizeAdd);
		memset(pFileBuffer, 0, FileSize + FileSizeAdd);
		free(pFileBuffer1);
		if (!pFileBuffer)
		{
			::MessageBoxA(0, "分配空间失败!", "", 0);
			fclose(pFile);
			return NULL;
		}
		pFile = fopen(lpszFile, "rb");
		if (!pFile)
		{
			::MessageBoxA(0, "无法打开 EXE 文件!", "", 1);
			return 0;
		}
		n = fread(pFileBuffer, FileSize, 1, pFile);
	}
	if (!n)
	{
		::MessageBoxA(0, "读取数据失败!", "", 0);
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//关闭文件
	fclose(pFile);
	return pFileBuffer;
}
//添加SEH反调试
void Anti_Debugg_Dialog::OnBnClickedButton1()
{
	// TODO:  在此添加控件通知处理程序代码
	CString ProPath;
	mExeEditBrowse.GetWindowText(ProPath);
	char* path = DataHs.CStringToCharSz(ProPath);
	pFileBuffer = AntiPEFileToMemory(path, 1);
	FindEmptyCode();
	if (!FindEmptyDataAndAddData())
	{
		AfxMessageBox("没有找到空白数据区域，无法添加反调试");
		return;
	}
	ModefyAllShellCode();
	if (WriterToPEFileAndDisk("seh_add.exe"))
	{
		AfxMessageBox("成功添加SEH反调试，程序名为seh_add.exe");
		return;
	}
	return;
}

void Anti_Debugg_Dialog::TLSModefyMem(char* path)
{
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory_TLS = NULL;
	PIMAGE_TLS_DIRECTORY32 pTLS = NULL;
	AntiPEFileToMemory(path, 1);
	//获取目录表结构，修改值
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + 0x4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	ImageBase = pOptionHeader->ImageBase;
	SectionNum = pPEHeader->NumberOfSections;
	//定位到最后段结构体
	PIMAGE_SECTION_HEADER tpSectionHeader = pSectionHeader;
	for (int i = 0; i < SectionNum; i++)
	{
		tpSectionHeader++;
	}
	tpSectionHeader--;
	tpSectionHeader->Characteristics = 0xE0000060;
	tpSectionHeader->SizeOfRawData += pOptionHeader->FileAlignment;
	//找到TLS目录
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)pOptionHeader->DataDirectory;
	pDataDirectory_TLS = (PIMAGE_DATA_DIRECTORY)&pDataDirectory[9];
	pDataDirectory_TLS->Size = 0x18;
	DWORD FileBeforeSize = FileSize;
	pDataDirectory_TLS->VirtualAddress = DataHs.FoaToRva(pFileBuffer, FileBeforeSize);
	//在文件末尾添加TLS结构信息
	DWORD StartAddr = pDataDirectory_TLS->VirtualAddress + ImageBase;
	pTLS = (PIMAGE_TLS_DIRECTORY32)((DWORD)pFileBuffer + FileBeforeSize);
	pTLS->StartAddressOfRawData = StartAddr + 0x18;
	pTLS->EndAddressOfRawData = pTLS->StartAddressOfRawData + 0x4;
	pTLS->AddressOfIndex = pTLS->EndAddressOfRawData + 0x4;
	pTLS->AddressOfCallBacks = pTLS->AddressOfIndex + 0x4;
	pTLS->SizeOfZeroFill = 0x0;
	pTLS->Characteristics = 0x0;
	//计算出两个函数的地址并修改shellcode
	DWORD MessageBoxAddr = (DWORD)GetProcAddress(GetModuleHandle("USER32.dll"), "MessageBoxA");
	DWORD ExitProcessAddr = (DWORD)GetProcAddress(GetModuleHandle("KERNEL32.dll"), "ExitProcess");
	//MessageBoxA地址-startaddr-0x27,off:0x23
	MessageBoxAddr = MessageBoxAddr - StartAddr - 0x27;
	*((DWORD*)(TLSCode + 0x23)) = MessageBoxAddr;
	//ExitProcess地址-startaddr-0x2F,off:0x2B
	ExitProcessAddr = ExitProcessAddr - StartAddr - 0x2F;
	*((DWORD*)(TLSCode + 0x2B)) = ExitProcessAddr;
	//字符串1：startaddr+0x70，off：0x16
	*((DWORD*)(TLSCode + 0x16)) = StartAddr+0x70;
	//字符串2：startaddr+0x80,off:0x1B
	*((DWORD*)(TLSCode + 0x1B)) = StartAddr + 0x80;
	//callback地址
	*((DWORD*)((PBYTE)pTLS+ 0x24)) = StartAddr + 0x30;
	//拷贝shellcode
	memcpy(((PBYTE)pTLS + 0x30), TLSCode, 0x32);
	//拷贝字符串1
	char* c1 = "TLS CALLBACK";
	memcpy(((PBYTE)pTLS + 0x70), c1, strlen(c1));
	//拷贝字符串2
	char* c2 = "debugging";
	memcpy(((PBYTE)pTLS + 0x80), c2, strlen(c2));
	return;
}
//添加TLS反调试
void Anti_Debugg_Dialog::OnBnClickedButton6()
{
	// TODO:  在此添加控件通知处理程序代码
	CString ProPath;
	mExeEditBrowse.GetWindowText(ProPath);
	char* path = DataHs.CStringToCharSz(ProPath);
	TLSModefyMem(path);
	if (WriterToPEFileAndDisk("Tls_add.exe"))
	{
		AfxMessageBox("成功添加TLS反调试，程序名为Tls_add.exe");
		return;
	}
	return;
}
