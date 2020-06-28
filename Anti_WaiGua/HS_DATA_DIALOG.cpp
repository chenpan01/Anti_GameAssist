// HS_DATA_DIALOG.cpp : 实现文件
//

#include "stdafx.h"
#include "Anti_WaiGua.h"
#include "HS_DATA_DIALOG.h"
#include "afxdialogex.h"
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
using namespace std;
// HS_DATA_DIALOG 对话框
#ifdef _DEBUG
#endif

IMPLEMENT_DYNAMIC(HS_DATA_DIALOG, CDialogEx)

HS_DATA_DIALOG::HS_DATA_DIALOG(CWnd* pParent /*=NULL*/)
	: CDialogEx(HS_DATA_DIALOG::IDD, pParent)
{

}

HS_DATA_DIALOG::~HS_DATA_DIALOG()
{

}
BOOL HS_DATA_DIALOG::OnInitDialog()
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
	
	//HS_DATA_DIALOG::OnBnClickedOk();
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
void HS_DATA_DIALOG::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, mExeEditBrowse);
	DDX_Control(pDX, IDC_LIST2, mProListLeft);
	DDX_Control(pDX, IDC_LIST3, mProListRight);
}


BEGIN_MESSAGE_MAP(HS_DATA_DIALOG, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &HS_DATA_DIALOG::OnBnClickedButton1)
	ON_EN_CHANGE(IDC_MFCEDITBROWSE1, &HS_DATA_DIALOG::OnEnChangeMfceditbrowse1)
	ON_BN_CLICKED(IDC_BUTTON2, &HS_DATA_DIALOG::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &HS_DATA_DIALOG::OnBnClickedButton3)
END_MESSAGE_MAP()

// HS_DATA_DIALOG 消息处理程序
LPVOID HS_DATA_DIALOG::PEFileToMemory(LPSTR lpszFile)
{
	FILE *pFile = NULL;
	LPVOID pFileBuffer = NULL;
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
	pFileBuffer = malloc(FileSize);

	if (!pFileBuffer)
	{
		::MessageBoxA(0, "分配空间失败!", "", 1);
		fclose(pFile);
		return NULL;
	}
	//将文件数据读取到缓冲区
	size_t n = fread(pFileBuffer, FileSize, 1, pFile);
	if (!n)
	{
		::MessageBoxA(0, "读取数据失败!", "", 1);
		free(pFileBuffer);
		fclose(pFile);
		return NULL;
	}
	//关闭文件
	fclose(pFile);
	return pFileBuffer;
}
// FOA转换为RVA
DWORD HS_DATA_DIALOG::FoaToRva(PVOID PeBuffer, DWORD Foa)
{
	//定义必要的变量
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD SectionNum = 0;


	if (PeBuffer == NULL)
	{
		printf("(FoaToRva)PE buffer为空\n");
		return 0;
	}
	if (*((PWORD)(PeBuffer)) != IMAGE_DOS_SIGNATURE)
	{
		printf("(FoaToRva)不是有效的EXE文件\n");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)PeBuffer;

	if (*((PDWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(FoaToRva)不是有效的PE文件\n");
		return 0;
	}
	//PE标准头对象
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 0x4);
	SectionNum = pPEHeader->NumberOfSections;
	//PE可选头对象 PIMAGE_OPTIONAL_HEADER32 pOptionHeader
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER); 
	//获取头节表结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//遍历头节表结构，判断节表
	PIMAGE_SECTION_HEADER tpSectionHeader = pSectionHeader;

	if (Foa <= pOptionHeader->SizeOfHeaders)  
		return (DWORD)Foa;
	else
	for (int i = 0; i<SectionNum; i++)
	{
		if (Foa >= tpSectionHeader->PointerToRawData&&Foa <= tpSectionHeader->PointerToRawData + tpSectionHeader->SizeOfRawData)
		{
			return Foa - tpSectionHeader->PointerToRawData + tpSectionHeader->VirtualAddress;
		}
		tpSectionHeader++;
	}
	return 0;
}
// RVA转换为FOA
DWORD HS_DATA_DIALOG::RvaToFoa(PVOID PeBuffer, DWORD Rva)
{
	//定义必要的变量
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD SectionNum = 0;

	if (PeBuffer == NULL)
	{
		printf("(RvaToFoa)PE buffer为空\n");
		return 0;
	}

	if (*((PWORD)PeBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("(RvaToFoa)不是有效的EXE文件\n");
		return 0;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)PeBuffer;

	if (*((PWORD)((DWORD)pDosHeader + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(RvaToFoa)不是有效的PE文件\n");
		return 0;
	}
	//PE文件头对象
	pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 0x4);
	SectionNum = pPEHeader->NumberOfSections;
	//PE可选头对象 PIMAGE_OPTIONAL_HEADER32 pOptionHeader
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER); 
	//获取头节表结构
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//遍历头节表结构，判断节表
	PIMAGE_SECTION_HEADER tpSectionHeader = pSectionHeader;

	if (Rva <= pOptionHeader->SizeOfHeaders)  
		return (DWORD)Rva;
	else
	for (int i = 0; i<SectionNum; i++)
	{
		if (Rva >= tpSectionHeader->VirtualAddress&&Rva <= tpSectionHeader->VirtualAddress + tpSectionHeader->Misc.VirtualSize)
		{
			return Rva - tpSectionHeader->VirtualAddress + tpSectionHeader->PointerToRawData;
		}
		tpSectionHeader++;
	}
	return 0;
}
BOOL HS_DATA_DIALOG::TraverseFuncAndData(LPVOID pFileBuffer)
{
	// 初始化PE头部结构体
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL,tpSectionHeader=NULL;
	// 初始化IMAGE_BUFFER指针(temparay)
	LPVOID pTempImagebuffer = NULL;

	if (!pFileBuffer)
	{
		::MessageBoxA(0, "(TraverseFuncAndData)读取到内存的pfilebuffer无效", "", 2);
		return FALSE;
	}
	// 判断是否是可执行文件
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)  
	{
		::MessageBoxA(0, "(TraverseFuncAndData)不含MZ标志，不是exe文件！", "", 2);
		return FALSE;
	}
	//强制结构体类型转换pDosHeader
	pDosHeader = PIMAGE_DOS_HEADER(pFileBuffer);
	//判断是否为PE标志
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE) 
	{			
		::MessageBoxA(0, "(TraverseFuncAndData)不是有效的PE标志！", "", 2);
		return FALSE;
	}
	// 强制结构体类型转换
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEFileHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEFileHeader->SizeOfOptionalHeader);
	tpSectionHeader = pSectionHeader;
	//代码段起始地址
	TextStartAddress = pSectionHeader->PointerToRawData;
	TextEndAddress = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData;
	//计算OEP
	OEP = pOptionHeader->AddressOfEntryPoint + pOptionHeader->ImageBase;
	ImageBase = pOptionHeader->ImageBase;
	int Funi = 0;
	int Datai = 0;
	//寻找函数位置
	for (DWORD i = TextStartAddress; i < TextEndAddress-2; i++)
	{
		//::MessageBoxA(0,"函数循环","",1);
		//获取函数头部信息
		pFuncHeader = (_FuncHeader*)((DWORD)pFileBuffer + i);
		//判断是否为函数头部
		if (pFuncHeader->p1 == 0x55 && pFuncHeader->p2 == 0x89 && pFuncHeader->p3 == 0xE5 || pFuncHeader->p1 == 0x53 && pFuncHeader->p2 == 0x56 && pFuncHeader->p3 == 0x57 && pFuncHeader->p4 == 0x55 || pFuncHeader->p1 == 0x55 && pFuncHeader->p2 == 0x8B && pFuncHeader->p3 == 0xEC)
		{
			//把FOA地址转换成VA
			DWORD FuncAddr = FoaToRva(pFileBuffer, i) + ImageBase;
			if (FuncAddr>OEP)
			{
				//ModFunAddr[Funi++] = FuncAddr;
				CString str;
				str.Format("Func:%x",FuncAddr);
				//往列表添加数据
				int count=mProListLeft.AddString(str);
				//设置FOA值
				mProListLeft.SetItemData(count, i);
			}
			//::MessageBoxA(0, "mProListLeft.AddString", "", 1);
		}
		
	}
	DWORD DataAddr;
	DWORD DataEnd;
	//找到数据段的起始和结束位置
	for (int i = 0; i < pPEFileHeader->NumberOfSections; i++, tpSectionHeader++)
	{
		int num = 0;
		char* name01 = ".data";
		char name[9] = { 0 };
		memcpy(name, tpSectionHeader->Name, 8);
		if (!strcmp(name, name01))
		{
			//起始地址
			DataAddr = FoaToRva(pFileBuffer, tpSectionHeader->PointerToRawData) + ImageBase;
			//结束地址
			DataEnd = FoaToRva(pFileBuffer, tpSectionHeader->PointerToRawData + tpSectionHeader->SizeOfRawData) + ImageBase;
		}
	}
	//遍历代码段，找到mov指令
	for (DWORD i = TextStartAddress; i < TextEndAddress - 2; i++)
	{
		BYTE* IsMov = (BYTE*)((DWORD)pFileBuffer + i);
		DWORD* MovValue = (DWORD*)((DWORD)pFileBuffer + i + 1);
		//0xB8到0xBF为mov指令的硬编码
		if (0xB8 <= *IsMov&&*IsMov<0xC0)
		{
			if (DataAddr <= *MovValue&&*MovValue<DataEnd)
			{
				BYTE* DataLast = (BYTE*)((DWORD)pFileBuffer + i + 1);
				CString str;
				str.Format("Data:%x", *MovValue);
				//往列表添加数据
				int count = mProListLeft.AddString(str);
				//对索引项设值
				mProListLeft.SetItemData(count, i+1);

			}
		}
	}
	return true;
}
//把选中的项添加到右边的列表中
void HS_DATA_DIALOG::OnBnClickedButton1()
{
	// TODO:  在此添加控件通知处理程序代码
	//显示在列表(不显示系统库API)中，显示规则,完善添加功能
	CString str;
	int index = mProListLeft.GetCurSel();
	if (index == -1)
	{
		::MessageBoxA(0,"请选择要保护的函数货数据","温馨提示",0);
		return;
	}
	//如果没有重复选
	if (IsSelect[index] == -1)
	{
		mProListLeft.GetText(index, str);
		int count = mProListRight.AddString(str);
		DWORD value=mProListLeft.GetItemData(index);
		//对索引项设值
		mProListRight.SetItemData(count, value);
		IsSelect[index] = 1;
	}
	//如果该项已选
	else
	{
		::MessageBoxA(0, "该数据已在右边列表中", "温馨提示", 0);
	}
	return ;
}

//把EXE文件中的函数和数据显示在左边列表中
void HS_DATA_DIALOG::OnEnChangeMfceditbrowse1()
{
	// TODO:  在此添加控件通知处理程序代码
	//得到程序路径
	mExeEditBrowse.GetWindowText(ExePath);
	CStringA tmp = ExePath;
	char* pp = tmp.GetBuffer();
	//更新列表内容
	mProListLeft.ResetContent();
	mProListRight.ResetContent();
	//把exe文件加载到内存中
	pPeBuffer = PEFileToMemory(pp);
	//往左边列表中添加函数和数据信息
	TraverseFuncAndData(pPeBuffer);
	memset(IsSelect,-1,SZLEN);
	return;
}
DWORD HS_DATA_DIALOG::ReverseData(DWORD value)
{
	DWORD ans = 0;
	DWORD unit[4] = { 0x1000000, 0x10000, 0x100,0x1};
	DWORD Mod = 0x100;
	for (int i = 0; i < 4; i++)
	{
		byte b = value%Mod;
		ans += unit[i] * b;
		value /= Mod;
	}
	return ans;
}
CHAR* HS_DATA_DIALOG::DWORDToString(DWORD value)
{
	DWORD tvalue = value;
	char ans[10];
	char* tans = (char*)malloc(10);
	memset(ans, '\0', 10);
	//数组下标跟数组值相同
	char H[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	int pos = 0;
	while (tvalue % 0x10)
	{
		BYTE end = tvalue % 0x10;
		for (int j = 0; j<16; j++)
		{
			if (end == j)
			{
				ans[pos] = H[j];
				pos++;
			}
		}
		tvalue /= 0x10;
	}
	int i = 0;
	for (int j = strlen(ans) - 1; j>-1; j--, i++)
	{
		tans[i] = ans[j];
	}
	tans[i] = '\0';
	return tans;
}
DWORD HS_DATA_DIALOG::CharToDword(char* value)
{
	DWORD ans = 0;
	//数组下标跟数组值相同
	char H[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	char h[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	int len = strlen(value);
	int pos = 1;
	for (int i = len - 1; i >= 0; i--)
	{
		for (int j = 0; j<16; j++)
		{
			if (h[j] == value[i] || H[j] == value[i])
			{
				ans += j*pos;
				pos *= 0x10;
			}
		}
	}
	return ans;
}
CHAR* HS_DATA_DIALOG::CStringToCharSz(CString value)
{
	char* p = (char*)malloc(0x100);
	memset(p,0,0x100);
	memcpy(p, value, value.GetLength());
	return p;
}
//修改函数地址和数据地址
void HS_DATA_DIALOG::OnBnClickedButton2()
{
	if (!mProListRight.GetCount())
	{
		::MessageBoxA(0, "请选择要保护的函数或数据", "消息",2);
	}
	//获取到所有的函数、数据地址并把他们区分开了
	CString Liststring;
	int Funi = 0, Datai = 0;
	for (int i = 0; i < mProListRight.GetCount(); i++)
	{
		mProListRight.GetText(i, Liststring);
		int len = Liststring.GetLength();
		if (Liststring.GetAt(0) == 'F')
		{
			//截取函数地址
			CString Fun = Liststring.Right(len - 5);
			//CStringA tmp=
			char* ValueSz = CStringToCharSz(Fun);
			DWORD RealValue = CharToDword(ValueSz);			
			for (int j = TextStartAddress; j < TextEndAddress; j++)
			{
				BYTE* Diss = (BYTE*)((DWORD)pPeBuffer + j);
				if (*Diss == 0xE8)
				{
					//call下一行汇编代码地址
					DWORD NextDiss = FoaToRva(pPeBuffer, j + 5) + ImageBase;
					DWORD* CodeContext = (DWORD*)((DWORD)pPeBuffer+j+1);
					BYTE* FunLastData = (BYTE*)((DWORD)pPeBuffer + j + 1);
					//call 后接地址
					DWORD CallValue = RealValue - NextDiss;
					if (*CodeContext == CallValue)
					{
						//::MessageBoxA(0, "修改", "右边列表值", 2);
						AllFuncData[lenFun].FunAddr = FoaToRva(pPeBuffer, j + 1) + ImageBase;
						AllFuncData[lenFun++].RealData = *FunLastData;
						*FunLastData = rand() % 0x100;
					}
				}
			}
		}
		else if (Liststring.GetAt(0) == 'D')
		{
			//截取数据地址
			CString Data = Liststring.Right(len - 5);
			char* ValueSz = CStringToCharSz(Data);
			//::MessageBoxA(0, ValueSz, "Data ValueSz", 2);
			DWORD DataFoa = mProListRight.GetItemData(i);
			BYTE* LastByte = (BYTE*)((DWORD)pPeBuffer + DataFoa);
			//对修改结构体赋值
			AllModData[lenData].ModAddr = FoaToRva(pPeBuffer, DataFoa) + ImageBase;
			AllModData[lenData++].RealData = *LastByte;
			*LastByte = rand() % 0x100;
		}
	}
	CStringA tmp;
	tmp = ExePath;
	char *Path = tmp.GetBuffer();
	int i = 0;
	string FuPath = "_Pro.exe";
	for (i = 0; i<strlen(Path)-4; i++)
	{
		tmpPath[i] = Path[i];
	}
	//附加上保护名
	for (int j = 0; j < 8; j++)
	{
		tmpPath[j + i] = FuPath.at(j);
	}
	//写入磁盘
	if (!MemoryToFile(pPeBuffer, FileSize, tmpPath))
	{
		printf("MemoryToFile is fail\n");
	}
	AfxMessageBox(_T("PE文件保护成功"), MB_OKCANCEL | MB_ICONQUESTION, 0);
	return ;
}
BOOL HS_DATA_DIALOG::MemoryToFile(PVOID pPEbuffer, DWORD filesize, LPSTR filePath)
{
	FILE* fp;
	fp = fopen(filePath, "wb");
	if (!fp)
	{
		::MessageBoxA(0, "(MemoryToFile) 无法打开 EXE 文件!", "", 1);
		return 0;
	}
	else
	{
		fwrite(pPEbuffer, filesize, 1, fp);
	}
	fclose(fp);
	return 1;
}

//运行已保护软件
void HS_DATA_DIALOG::OnBnClickedButton3()
{
	STARTUPINFO si = {};
	//操作进程的信息结构体
	PROCESS_INFORMATION pi = {};
	//创建进程，并挂起
	CreateProcess(tmpPath, 0, 0, 0, FALSE, CREATE_SUSPENDED,0, 0, &si, &pi);
	DWORD dwWrite = 0;
	for (int i = 0; i<lenFun; i++)
	{
		if (!::WriteProcessMemory(pi.hProcess, (LPVOID)AllFuncData[i].FunAddr, &AllFuncData[i].RealData, 1, &dwWrite))
		{
			printf("Func WriteProcessMemory is fail\n");
		}
		else
			printf("Func WriteProcessMemory is success\n");
	}
	//恢复数据
	for (int i = 0; i<lenData; i++)
	{
		if (!::WriteProcessMemory(pi.hProcess, (LPVOID)AllModData[i].ModAddr, &AllModData[i].RealData, 1, &dwWrite))
		{
			printf("Data WriteProcessMemory is fail\n");
		}
		else
			printf("Data WriteProcessMemory is success\n");
	}
	//运行进程
	ResumeThread(pi.hThread);
	return ;
}
