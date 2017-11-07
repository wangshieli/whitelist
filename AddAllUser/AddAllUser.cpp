#define   INITGUID 
#include <stdio.h>
#include <windows.h>
#include <GPEdit.h>
//#include<Guiddef.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <io.h>
#include <iostream>

using namespace std;

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
	status = RegOpenKeyEx(hGPOKey, "Software\\Policies\\Google\\Chrome\\ExtensionInstallSources", 0,
		KEY_WRITE, &hKey);

	// 如果没有此项，直接创建添加，不需要对比 如果项已经存在，对比之后添加
	if (status != ERROR_SUCCESS)
	{
		status = RegCreateKeyEx(hGPOKey, "Software\\Policies\\Google\\Chrome\\ExtensionInstallSources", 0,
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
	//struct value_node* pNode = pHead;
	//while (pNode)
	//{
	//	char cckey[8] = {0};
	//	_itoa_s(++nHasExist, cckey, 8, 10);
	//	printf("新增加id:%s\n", pNode->pValue);
	//	status = RegSetValueEx(hKey, cckey, NULL, REG_SZ, (const unsigned char*)pNode->pValue, strlen(pNode->pValue) + 1);
	//	pNode = pNode->pNext;
	//}
	const char* pV = "<all_urls>";

	RegSetValueEx(hKey, "1", NULL, REG_SZ, (const unsigned char*)pV, strlen(pV) + 1);

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

void main(int argc, char* argv[])
{
	ModifyWhitelist();
	system("pause");
}