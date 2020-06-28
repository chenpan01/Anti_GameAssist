
// Anti_WaiGuaDlg.h : 头文件
//

#pragma once
#include "TabSheet.h"
#include "HS_DATA_DIALOG.h"
#include "PRO_TEXT_Dialog.h"
#include "Free_Dll_Dialog.h"
#include "Anti_Debugg_Dialog.h"
#include "ToolAndOpenMore.h"

// CAnti_WaiGuaDlg 对话框
class CAnti_WaiGuaDlg : public CDialogEx
{
// 构造
public:
	CAnti_WaiGuaDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_ANTI_WAIGUA_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CTabSheet m_tab;
	HS_DATA_DIALOG HS_DATA;
	PRO_TEXT_Dialog Pro_Code;
	Free_Dll_Dialog Free_Dll;
	Anti_Debugg_Dialog AntiDebug;
	ToolAndOpenMore TAOM;
};
