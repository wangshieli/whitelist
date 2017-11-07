#define   INITGUID 
#include <stdio.h>
#include <windows.h>
#include <GPEdit.h>
//#include<Guiddef.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <io.h>
#include <iostream>
#include <curl\curl.h>
#include "cJSON.h"
#include "md5.h"

using namespace std;

#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "psapi.lib")

#define ADL_VERSION "\n   awlist.exe v0.0.2\n"
#define ADL_HELP "\n   自动设置chrome白名单工具，支持WIN7/WIN10\n"
#define ORDER_ERROR "\n   操作指令：\n"	\
				"     * -v/-V 获取控件版本信息\n"	\
				"     * -h/-H 获取帮助信息\n"


#define ADM_URL	"http://chex.oss-cn-shanghai.aliyuncs.com/host/chrome.adm"
#define ADMX_URL	"http://chex.oss-cn-shanghai.aliyuncs.com/host/chrome.admx"
#define ADML_URL	"http://chex.oss-cn-shanghai.aliyuncs.com/host/chrome.adml"
#define EXTERN_ID_URL "https://wwwphpapi-0.disi.se/v1/extension/browser/codes"

#define ADML_PATH	"C:\\Windows\\PolicyDefinitions\\zh-CN\\chrome.adml"
#define ADMX_PATH	"C:\\Windows\\PolicyDefinitions\\chrome.admx"

#define ADMX_MD5	"2d2ec955a2d7dad5715b2e94b69bbd60"
#define ADML_MD5	"7ac074163b4b76d20e9f92e2dc27e070"

#define ADML_PATH_TEST	"D:\\chrome.adml"
#define ADMX_PATH_TEST	"D:\\chrome.admx"
#define ADM_PATH_TEST	"D:\\chrome.adm"
//#define ADM_FILE	"C:\\WINDOWS\\system32\\grouppolicy\\Adm\\chrome.adm"
#define REG_CHROME_ITEM	"Software\\Policies\\Google\\Chrome\\ExtensionInstallWhitelist"

#define MY_ALIGN(size, boundary) (((size) + ((boundary) - 1 )) & ~((boundary) - 1))

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 255

typedef size_t (* TFun)(void* , size_t , size_t , void *);

typedef struct _recvbuffer
{
	size_t nrecved;
	char* precv;
}RecvBuffer;

struct value_node
{
	char* pValue;
	struct value_node* pPre;
	struct value_node* pNext;
};

struct value_node* pHead = NULL;

int nHasExist = 0;

DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;

char ChromePath[MAX_PATH];

BOOL Execmd(char* cmd, char** result)
{
	int readlen = 0;
	int readtotal = 0;
	char buffer[128];
	char* pUserData = (char*)malloc(1024);
	ZeroMemory(pUserData, 1024);
	FILE *pipe = _popen(cmd, "r");
	if (!pipe)
	{
		free(pUserData);
		pUserData = NULL;
		return FALSE;
	}

	while (!feof(pipe))
	{
		if (fgets(buffer, 128, pipe))
		{
			readlen = strlen(buffer) + 1;
			readtotal += readlen;
			if (readtotal > (int)_msize(pUserData))
			{
				int RelAllocByteSize = MY_ALIGN((readtotal + 1), 8);
				pUserData = (char*)realloc(pUserData, RelAllocByteSize);
			}
			strcat_s(pUserData, readtotal, buffer);
		}
	}

	_pclose(pipe);
	*result = pUserData;

	return TRUE;
}

size_t curl_recv_function(void* buffer, size_t size, size_t nmemb, void *_pRecvBuffer)
{
	RecvBuffer* pRecvBuffer = (RecvBuffer*)_pRecvBuffer;
	size_t recvlen = MY_ALIGN((pRecvBuffer->nrecved + (size * nmemb) + 1), 8);
	if (_msize(pRecvBuffer->precv) < recvlen)
		pRecvBuffer->precv = (char*)realloc(pRecvBuffer->precv, recvlen);
	if (pRecvBuffer->precv)
	{
		memcpy(pRecvBuffer->precv + pRecvBuffer->nrecved, buffer, size * nmemb);
		pRecvBuffer->nrecved += (nmemb * size);
		memset(pRecvBuffer->precv + pRecvBuffer->nrecved, 0x00, 1);
	}

	return size * nmemb;
}

size_t curl_down_function(void* buffer, size_t size, size_t nmemb, void *ptr)
{
	FILE* f = (FILE*)ptr;
	fwrite(buffer, 1, nmemb * size, f);
	return size * nmemb;
}

BOOL biu_down_file(const char* pUrl, TFun curl_func, void* param)
{
	CURL *curl;
	CURLcode code;

	curl = curl_easy_init();
	if (!curl)
	{
		return FALSE;
	}

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, FALSE);

	curl_easy_setopt(curl, CURLOPT_URL, pUrl);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_func);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, param);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 8);

	code = curl_easy_perform(curl);
	if (CURLE_OK != code)
	{
		//fprintf(stderr, "GET请求返回值:%d\n", code);
		//switch (code)
		//{
		//case CURLE_COULDNT_CONNECT:
		//	fprintf(stderr, "不能连接到目标主机\n");
		//break;
		//default:
		//	break;
		//}
//		fclose(fptr);
		curl_easy_cleanup(curl);
		return FALSE;
	}

//	fclose(fptr);
	curl_easy_cleanup(curl);
	return TRUE;
}

BOOL CompareValuse(const char* _pValue)
{
	struct value_node* pNode = pHead;
	while (pNode)
	{
		if (strcmp(pNode->pValue, _pValue) == 0)
		{
			if (pNode == pHead)
			{
				pHead = pHead->pNext;
				if (pHead)
					pHead->pPre = NULL;
			}else
			{
				pNode->pPre->pNext = pNode->pNext;
				if (pNode->pNext)
					pNode->pNext->pPre = pNode->pPre;
			}

			return FALSE;
		}
		pNode = pNode->pNext;
	}
	
	return TRUE;
}
 
void QueryKey(HKEY hKey) 
{ 
    char    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
    DWORD    cchClassName = MAX_PATH;  // size of class string 
    DWORD    cSubKeys=0;               // number of subkeys 
    DWORD    cbMaxSubKey;              // longest subkey size 
    DWORD    cchMaxClass;              // longest class string 
    DWORD    cValues;              // number of values for key 
    DWORD    cchMaxValue;          // longest value name 
    DWORD    cbMaxValueData;       // longest value data 
    DWORD    cbSecurityDescriptor; // size of security descriptor 
    FILETIME ftLastWriteTime;      // last write time 
 
    DWORD i, retCode; 
 
    char  achValue[MAX_VALUE_NAME]; 
    DWORD cchValue = MAX_VALUE_NAME; 
 
    retCode = RegQueryInfoKey(
        hKey,                    // key handle 
        achClass,                // buffer for class name 
        &cchClassName,           // size of class string 
        NULL,                    // reserved 
        &cSubKeys,               // number of subkeys 
        &cbMaxSubKey,            // longest subkey size 
        &cchMaxClass,            // longest class string 
        &cValues,                // number of values for this key 
        &cchMaxValue,            // longest value name 
        &cbMaxValueData,         // longest value data 
        &cbSecurityDescriptor,   // security descriptor 
        &ftLastWriteTime);       // last write time 
 
    if (cValues) 
    {
		nHasExist = cValues;

        for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
        { 
            cchValue = MAX_VALUE_NAME; 
            achValue[0] = '\0'; 
            retCode = RegEnumValue(hKey, i, 
                achValue, 
                &cchValue, 
                NULL, 
                NULL,
                NULL,
                NULL);
 
            if (retCode == ERROR_SUCCESS ) 
            { 
				char szBuffer[255] = { 0 };
				DWORD dwNameLen = 255;
				DWORD rQ = RegQueryValueEx(hKey, achValue, 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				if (rQ == ERROR_SUCCESS)
				{
					CompareValuse(szBuffer);
				}
            } 
        }
    }
}

LRESULT ModifyWhitelist()
{
	::CoInitialize(NULL);
	LRESULT status;
	LRESULT hr = S_OK;
	IGroupPolicyObject*pGPO = NULL;
	hr = CoCreateInstance(CLSID_GroupPolicyObject, NULL, CLSCTX_INPROC_SERVER, IID_IGroupPolicyObject, (LPVOID*)&pGPO);
	if (hr == S_OK)
	{
	//	cout << "GPO创建成功\n";
	}
	else
	{
	//	cout << "GPO创建失败\n";
		return E_FAIL;
	}
//	DWORD dwSection = GPO_SECTION_USER;
	DWORD dwSection = GPO_SECTION_MACHINE;
	HKEY hGPOKey = 0;
	hr = pGPO->OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY);
	if (SUCCEEDED(hr))
	{
	//	cout << "打开本地机器成功\n";
	}
	else
	{
	//	cout << "打开本地失败\n";
		cout << GetLastError() << endl;
		return E_FAIL;
	}
	hr = pGPO->GetRegistryKey(dwSection, &hGPOKey);
	if (SUCCEEDED(hr))
	{
	//	cout << "加载注册表成功\n";
	}
	else
	{
	//	cout << "加载注册表失败\n";
		return E_FAIL;
	}

	HKEY hKey = NULL;

	// Machine\Software\Policies\Google\Chrome\ExtensionInstallSources
	// "**delvals."=" "
	// "1"="<all_urls>"
	status = RegOpenKeyEx(hGPOKey, "Software\\Policies\\Google\\Chrome\\ExtensionInstallWhitelist", 0,
		KEY_WRITE, &hKey);

	// 如果没有此项，直接创建添加，不需要对比 如果项已经存在，对比之后添加
	if (status != ERROR_SUCCESS)
	{
		status = RegCreateKeyEx(hGPOKey, "Software\\Policies\\Google\\Chrome\\ExtensionInstallWhitelist", 0,
			NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
		if (status == S_OK)
		{
		//	cout << "创建键值成功\n";
		}
		else
		{
		//	cout << "创建键值失败\n";
			return E_FAIL;
		}
	}

	// 必须字段
	const char* pValue01 = " ";
	status = RegSetValueEx(hKey, "**delvals.", NULL, REG_SZ, (const unsigned char*)pValue01, strlen(pValue01) + 1);

	// 添加字段，根据情况循环
	struct value_node* pNode = pHead;
	while (pNode)
	{
		char cckey[8] = {0};
		_itoa_s(++nHasExist, cckey, 8, 10);
		printf("新增加id:%s\n", pNode->pValue);
		status = RegSetValueEx(hKey, cckey, NULL, REG_SZ, (const unsigned char*)pNode->pValue, strlen(pNode->pValue) + 1);
		pNode = pNode->pNext;
	}

	status = RegCloseKey(hKey);

	GUID Registerid = REGISTRY_EXTENSION_GUID;
	GUID guid;
	CoCreateGuid(&guid);

	RegCloseKey(hGPOKey);

	status = pGPO->Save(TRUE, TRUE, &Registerid, &guid);
	pGPO->Release();
	::CoUninitialize();

	return S_OK;
}

// true找到了并且已经关闭  false没有找到
BOOL CloseChromeExe()
{
	PROCESSENTRY32 pe32;
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(pe32);

	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		printf("创建进程映射失败\n");
		return FALSE;
	}

	BOOL bMode = ::Process32First(hProcessSnap, &pe32);
	while (bMode)
	{
		if (0 == strcmp("chrome.exe", pe32.szExeFile))
		{
			HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
			GetModuleFileNameEx(ProcessHandle, NULL, ChromePath, MAX_PATH);
		//	printf("%s\n", ChromePath);
		//	printf("%d\n", GetLastError());
			CloseHandle(ProcessHandle);
			//TerminateProcess(ProcessHandle, 0);
			char *pInfo = NULL;
			Execmd("taskkill /im chrome.exe /f", &pInfo);
			if (NULL != pInfo)
			{
			//	printf("%s\n", pInfo);
				free(pInfo);
				pInfo = NULL;
			}
			CloseHandle(hProcessSnap);
			return TRUE;
			//HANDLE ProcessHandle = OpenProcess(PROCESS_TERMINATE | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
			//TerminateProcess(ProcessHandle, 0);
		}

		bMode = ::Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);

	return FALSE;
}

BOOL needdownload(char* psPath, char* pmd5)
{
	FILE* pFileEx = NULL;
	fopen_s(&pFileEx, psPath, "rb");
	if (pFileEx == NULL)
	{
		//文件不存在重新下载
		return FALSE;
	}else
	{
		//文件存在
		fclose(pFileEx);
		string md5value = MD5(ifstream(psPath, ios::binary)).toString();
		if (strcmp(md5value.c_str(), pmd5) == 0)
		{
			//不需要重新下载
			return TRUE;
		}
		// 重新下载
		DeleteFile(psPath);

		return FALSE;
	}

	return TRUE;
}

void main(int argc, char* argv[])
{
	if (argc == 2)
	{
		if (argv[1][0] == '-')
		{
			switch (tolower(argv[1][1]))
			{
			case 'v':
				{
					fprintf(stderr, "%s\n", ADL_VERSION);
					return ;
				}
				break;
			case 'h':
				{
					fprintf(stderr, "%s\n", ADL_HELP);
					return ;
				}
				break;
			default:
				{
					fprintf(stderr, "%s\n", ORDER_ERROR);
					return ;
				}
				break;
			}
		}
	}

	char* pInfo = NULL;
	while (!needdownload(ADMX_PATH, ADMX_MD5))
	{
		Sleep(1000*2);
		FILE* fptr;
		fopen_s(&fptr, ADMX_PATH, "wb");
		if (NULL == fptr)
		{
			printf("error %d\n", GetLastError());
			getchar();
			return ;
		}
		biu_down_file(ADMX_URL, curl_down_function, fptr);
		fclose(fptr);
	}
	while (!needdownload(ADML_PATH, ADML_MD5))
	{
		Sleep(2000);
		FILE* fptr;
		fopen_s(&fptr, ADML_PATH, "wb");
		if (NULL == fptr)
		{
			printf("error %d\n", GetLastError());
			getchar();
			return ;
		}
		biu_down_file(ADML_URL, curl_down_function, fptr);
		fclose(fptr);
	}

	//if (_access(ADM_PATH_TEST, 0) == -1)
	//{
	//	FILE* fptr;
	//	fopen_s(&fptr, ADM_PATH_TEST, "wb");
	//	if (NULL == fptr)
	//	{
	//		printf("error %d\n", GetLastError());
	//		getchar();
	//		return ;
	//	}
	//	biu_down_file(ADM_URL, curl_down_function, fptr);
	//	fclose(fptr);
	//}

	// 获取id
	RecvBuffer* pRecvBuffer = new RecvBuffer;
	pRecvBuffer->nrecved = 0;
	pRecvBuffer->precv = (char*)malloc(256);
	biu_down_file(EXTERN_ID_URL, curl_recv_function, pRecvBuffer);
	cJSON* root = cJSON_Parse(pRecvBuffer->precv);
	int n = cJSON_GetArraySize(root);
	for (int i = 0; i < n; i++)
	{
		struct value_node* pnode = new value_node;
		ZeroMemory(pnode, sizeof(value_node));
		cJSON* item = cJSON_GetArrayItem(root, i);
		pnode->pValue = item->valuestring;
	//	cout << pnode->pValue << endl;
		pnode->pNext = pHead;
		if (NULL != pHead)
			pHead->pPre = pnode;
		pHead = pnode;
	}

	free(pRecvBuffer->precv);
	delete pRecvBuffer;

	// 操作注册表
	HKEY hChreomeKey;
	if( RegOpenKeyEx( HKEY_LOCAL_MACHINE,
		REG_CHROME_ITEM,
		0,
		KEY_READ,
		&hChreomeKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hChreomeKey);
		RegCloseKey(hChreomeKey);
	}

	if (pHead)
	{
		ModifyWhitelist();
		//if (CloseChromeExe())
		//{
		//	Sleep(1000*2);
		//	ShellExecute(NULL, "open", ChromePath, NULL, NULL, SW_SHOWNORMAL);
		//}
		printf("更新完成\n");
	}else
	{
		printf("不需要更新\n");
	}

	cJSON_Delete(root);

	//getchar();
	system("pause");
}