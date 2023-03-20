#include "stdafx.h"

#include "customization_session.h"

#include "session_private_namespace.h"

#include "logger.h"

#include<iostream>

#include<fstream>

#include<bcrypt.h>

#include<wincrypt.h>

#include<string>

#include<TlHelp32.h>

#include<fileapi.h>

//#include<ntifs.h>

//#include<winternl.h>

namespace head

{

#include<winternl.h>

}

#pragma warning(disable : 4996) 

#pragma comment(lib, "bcrypt.lib")

#pragma comment(lib, "ntdll")

using namespace head;

using namespace std;

extern HINSTANCE g_hDllInst;

namespace Try

{

	//ofstream f1("C:\\Users\\prath\\OneDrive\\Desktop\\Detect\\a.txt", ios::app | ios::out);

	int pid;

	string pname, fname;

	string list1[] = { "encrypt","decrypt","bootkit","bitcoin"," BTC"," key"," tor","hacked","recovery","ransomware"," RSA" };

	string fnamel[] = { "recover","restore","decrypt","encrypted","crypt","ransom","satana","read","help","files","lock" };

	string fname2[] = { "A:","B:", "K:","L:","M:","N:","O:","P:","Q:","R:","S:","T:","U:","V:","W:","X:","Y:","Z:" };

	int c4 = 0, c = 0, c1 = 0, c2 = 0, c3 = 0, c5 = 0,c6=0, i1 = 0, i2 = 0, i3 = 0, i4 = 0, i5 = 0, i6 = 0,i7=0;

}

using namespace Try;

namespace

{

	/*//typedef NTSTATUS (NTAPI* NTALLOCATEVIRTUALMEMORY) (HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);*/

	//typedef int (WINAPI* CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

	typedef BOOL(WINAPI* WRITEFILE)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

	typedef BOOL(WINAPI* CRYPTENCRYPT)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);

	typedef BOOL(WINAPI* CRYPTACQUIRECONTEXTW)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);

	typedef DWORD(WINAPI* GETFILEATTRIBUTESW)(LPCWSTR);

	typedef DWORD(WINAPI* GETFILEATTRIBUTESEXW)(LPCWSTR,GET_FILEEX_INFO_LEVELS,LPVOID);

	typedef NTSTATUS(WINAPI* BCRYPTENCRYPT)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);

	typedef BOOL(WINAPI* PROCESS32FIRSTW)(HANDLE, LPPROCESSENTRY32W);

	typedef BOOL(WINAPI* PROCESS32NEXTW)(HANDLE, LPPROCESSENTRY32W);

	typedef BOOL(WINAPI* CRYPTGENRANDOM) (HCRYPTPROV, DWORD, BYTE*);

	typedef HANDLE(WINAPI* FINDFIRSTFILEEXW) (LPCWSTR,FINDEX_INFO_LEVELS,LPVOID,FINDEX_SEARCH_OPS,LPVOID,DWORD);

	

	typedef NTSTATUS(NTAPI* NTOPENFILE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);

	typedef NTSTATUS(NTAPI* NTCREATEFILE) (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,ULONG, ULONG, ULONG, ULONG, PVOID,ULONG );

	typedef HANDLE(WINAPI* FINDFIRSTFILEW) (LPCWSTR, LPWIN32_FIND_DATAW);

	typedef BOOL(WINAPI* FINDNEXTFILEW) (HANDLE, LPWIN32_FIND_DATAW);

	//CREATEFILEW pOriginalCreateFileW

	NTOPENFILE pOriginalNtOpenFile;

	WRITEFILE pOriginalWriteFile;

	CRYPTENCRYPT pOriginalCryptEncrypt;

	CRYPTACQUIRECONTEXTW pOriginalCryptAcquireContextW;

	CRYPTGENRANDOM pOriginalCryptGenRandom;

	BCRYPTENCRYPT pOriginalBCryptEncrypt;

	GETFILEATTRIBUTESW pOriginalGetFileAttributesW;

	GETFILEATTRIBUTESEXW pOriginalGetFileAttrib;

	PROCESS32FIRSTW pOriginalProcess32FirstW;

	PROCESS32NEXTW pOriginalProcess32NextW;

	FINDFIRSTFILEEXW pOriginalFindFirst;

	NTCREATEFILE pOriginalNtCreateFile;

	FINDFIRSTFILEW pOriginalFindFirstFile;

	FINDNEXTFILEW pOriginalFindNextFile;

	//NTALLOCATEVIRTUALMEMORY pOriginalAllocateVirtualMemory;

	

	/*void write(LPCWSTR a, int b)

	{

		char buffer[100];

		wcstombs(buffer, a, wcslen(a)<100? wcslen(a):100);

		char str[] = "PID: ";

		f1 << "PID: " << b;

		f1.write(buffer,wcslen(a));

		f1 << "\n";

	}*/

	void check1(string f)

	{

		wstring a = wstring(f.begin(), f.end());

		LPCWSTR a1 = a.c_str();

		OutputDebugString(a1);

		for (int i = 0;i < fname2->size();i++)

		{

			if (f.find(fname2->size()) != string::npos)

			{

				c6++;

				break;

			}

		}

	}

	bool findStringIC(const std::string& strHaystack, const std::string& strNeedle)

	{

		auto it = std::search(

			strHaystack.begin(), strHaystack.end(),

			strNeedle.begin(), strNeedle.end(),

			[](unsigned char ch1, unsigned char ch2) { return std::toupper(ch1) == std::toupper(ch2); }

		);

		return (it != strHaystack.end());

	}

	int check(string name)

	{

		for (int i = 0;i < fnamel->size();i++)

		{

			if (findStringIC(name, fnamel[i]))

			{

				return 1;

			}

		}

		return 0;

	}

	void write1(LPCVOID a, DWORD b, int c,string d)

	{

		const char* pString = reinterpret_cast<const char*>(a);

		ofstream f2("C:\\Program Files\\prath\\b.txt", ios::app | ios::out);

		string s = pString,name;

		int res,i;

		s = s.substr(0, 6000);

		name = d.substr(d.find_last_of("\\")+1);

		res=check(name);

		for (i = 0;i < list1->size();i++)

		{

			if (findStringIC(s, list1[i]))

			{

				OutputDebugString(L"Check");

				f2 <<c << " " << s << "\n";

				f2.close();

				if (fname == "")

				{

					fname = d;

				}

				else if (fname == d)

				{

					c += 1;

				}

				break;

			}

		}

		if ((c == 1 || res==1)&& c4==0)

		{

			c4 = 1;

			int id = GetCurrentProcessId();

			/*DWORD dw = static_cast<DWORD>(id);

			DebugActiveProcess(dw);

			system("pause");

			cout << "Suspended Process with PID:" << id;*/

			ofstream f5("C:\\Program Files\\prath\\trigger.txt", ios::app | ios::out);

			f5 <<pid << "\n";

			f5.close();

		}

	}

	void write2(int a, int b, string c, ofstream* f)

	{

		*f << to_string(a) + " " + to_string(b) + " " + c + "\n";

	}

	int WINAPI WriteFileHook(HANDLE hfile, LPCVOID lpbuffer, DWORD nofbytes, LPDWORD bytesw, LPOVERLAPPED over)

	{

		pid = GetCurrentProcessId();

		char buf[MAX_PATH];

		GetFinalPathNameByHandleA(hfile, buf, sizeof(buf), VOLUME_NAME_DOS);

		string f = buf;

		write1(lpbuffer, nofbytes, pid,f);

		return pOriginalWriteFile(hfile, lpbuffer, nofbytes, bytesw, over);

	}

	BOOL WINAPI CryptEncryptHook(HCRYPTKEY hkey, HCRYPTHASH hhash, BOOL fin, DWORD flag, BYTE* pbdata, DWORD* pwdatalen, DWORD dwbuflen)

	{

		OutputDebugString(L"CryptEncrypt");

		if (i1 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f5("C:\\Program Files\\prath\\trigger.txt", ios::app | ios::out);

			ofstream f3("C:\\Program Files\\prath\\c.txt", ios::app | ios::out);

			ofstream* f = &f3;

			f5 << pid << "\n";

			f5.close();

			write2(pid, 1, "CryptEncrypt", f);

			f3.close();

			i1 = 1;

		}

		return pOriginalCryptEncrypt(hkey, hhash, fin, flag,  pbdata, pwdatalen, dwbuflen);

	}

	DWORD WINAPI GetFileAttributesWHook(LPCWSTR lpfname)

	{

		c1++;

		if (c1 > 20 && i4 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f4("C:\\Program Files\\prath\\a.txt", ios::app | ios::out);

			ofstream* f = &f4;

			write2(pid, c1, "FileInfo", f);

			f4.close();

			i4 = 1;

		}

		return pOriginalGetFileAttributesW(lpfname);

	}

	BOOL WINAPI CryptAcquireContextWHook(HCRYPTPROV* phprov, LPCSTR container, LPCSTR provider, DWORD provtype, DWORD flag)

	{

		OutputDebugString(L"CryptAcq");

		if (i2 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f6("C:\\Program Files\\prath\\d.txt", ios::app | ios::out);

			ofstream* f = &f6;

			write2(pid, 1, "CryptAcquire", f);

			f6.close();

			i2 = 1;

		}

		return pOriginalCryptAcquireContextW(phprov, container, provider, provtype, flag);

	}

	NTSTATUS WINAPI BCryptEncryptHook(BCRYPT_KEY_HANDLE hkey, PUCHAR pbInp, ULONG cbInp, VOID* ppadinfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOut, ULONG cbOut, ULONG* pcbRes, ULONG dwFlags)

	{

		OutputDebugString(L"BCryptEncrypt");

		if (i3 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f7("C:\\Program Files\\prath\\c.txt", ios::app | ios::out);

			ofstream* f = &f7;

			ofstream f5("C:\\Program Files\\prath\\trigger.txt", ios::app | ios::out);

			f5 << pid << "\n";

			f5.close();

			write2(pid, 1, "BCryptEncrypt", f);

			f7.close();

			i3 = 1;

		}

		return pOriginalBCryptEncrypt(hkey, pbInp, cbInp, ppadinfo, pbIV, cbIV, pbOut, cbOut, pcbRes, dwFlags);

	}

	BOOL WINAPI Process32FirstWHook(HANDLE hSnap, LPPROCESSENTRY32W lppe)

	{

		OutputDebugString(L"Proc32");

		c2++;

		if (c2 > 10)

		{

			pid = GetCurrentProcessId();

			ofstream f8("C:\\Program Files\\prath\\e.txt", ios::app | ios::out);

			ofstream* f = &f8;

			write2(pid, c2, "Process32", f);

			f8.close();

			c2 = 0;

		}

		return pOriginalProcess32FirstW(hSnap, lppe);

	}

	BOOL WINAPI Process32NextWHook(HANDLE hSnap, LPPROCESSENTRY32W lppe)

	{

		OutputDebugString(L"Proc32");

		c2++;

		if (c2 > 10)

		{

			pid = GetCurrentProcessId();

			ofstream f9("C:\\Program Files\\prath\\e.txt", ios::app | ios::out);

			ofstream* f = &f9;

			write2(pid, c2, "Process32", f);

			f9.close();

			c2 = 0;

		}

		return pOriginalProcess32NextW(hSnap, lppe);

	}

	/*NTSTATUS NTAPI NtAllocateVirtualMemoryHook(HANDLE phand, PVOID* baseadd, ULONG_PTR zerobits, PSIZE_T regionsize, ULONG atype, ULONG prot)

	{

		if (prot == PAGE_READWRITE)

		{

			c3++;

			if (c3 > 50)

			{

				pid = GetCurrentProcessId();

				ofstream* f = &f3;

				write2(pid, c3, "AllocateVirtualMem", f);

				c3 = 0;

			}

		}

		return pOriginalAllocateVirtualMemory(phand, baseadd, zerobits, regionsize, atype, prot);

	}*/

	BOOL WINAPI CryptGenRandomHook(HCRYPTPROV hprov, DWORD dwlen, BYTE* pbuf)

	{

		OutputDebugString(L"CryptGen");

		if (i5 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f10("C:\\Program Files\\prath\\c.txt", ios::app | ios::out);

			ofstream* f = &f10;

			write2(pid, 1, "CryptGenRandom", f);

			f10.close();

			i5 = 1;

		}

		return pOriginalCryptGenRandom(hprov, dwlen, pbuf);

	}

	NTSTATUS NTAPI NtOpenFileHook(PHANDLE fhand, ACCESS_MASK dacc, POBJECT_ATTRIBUTES pobj, PIO_STATUS_BLOCK stat1, ULONG shareacc, ULONG options)

	{

		OutputDebugString(L"OpenFile");

		ofstream ft("C:\\Users\\prath\\Desktop\\open.txt",ios::app|ios::out);

		ft << "NtOpenFile";

		ft.close();

		pid = GetCurrentProcessId();

		char const* p = reinterpret_cast<char const*>(pobj->ObjectName);

		string name = p;

		check1(name);

		if (c6 >= 2 && i7 == 0)

		{

			ofstream f11("C:\\Program Files\\prath\\f.txt", ios::app | ios::out);

			ofstream* f = &f11;

			write2(pid, 1, "File", f);

			f11.close();

			i7 = 1;

		}

		return pOriginalNtOpenFile(fhand, dacc, pobj, stat1, shareacc, options);

	}

	HANDLE WINAPI FindFirstFileHook(LPCWSTR lpfname, FINDEX_INFO_LEVELS finfolevel, LPVOID filedata, FINDEX_SEARCH_OPS fsearch, LPVOID searchfilter, DWORD flags)

	{

		c5++;

		if (c5 > 20 && i6==0)

		{

			pid = GetCurrentProcessId();

			ofstream f12("C:\\Program Files\\prath\\g.txt", ios::app | ios::out);

			ofstream* f = &f12;

			write2(pid, c5, "FindFirst", f);

			f12.close();

			i6 = 1;

		}

		return pOriginalFindFirst(lpfname, finfolevel, filedata, fsearch, searchfilter, flags);

	}

	DWORD WINAPI GetFileAttributesExWHook(LPCWSTR lpfname, GET_FILEEX_INFO_LEVELS fileinfolevel, LPVOID fileinfo)

	{

		c1++;

		if (c1 > 20 && i4 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f13("C:\\Program Files\\prath\\a.txt", ios::app | ios::out);

			ofstream* f = &f13;

			write2(pid, c1, "FileInfo", f);

			f13.close();

			i4 = 1;

		}

		return pOriginalGetFileAttrib(lpfname,fileinfolevel,fileinfo);

	}

	NTSTATUS NTAPI NtCreateFileHook(PHANDLE fhand, ACCESS_MASK dacc, POBJECT_ATTRIBUTES objattr, PIO_STATUS_BLOCK iostatus, PLARGE_INTEGER alloc_size, ULONG fileatrr, ULONG shareacc, ULONG createdispo, ULONG createopt, PVOID eabuf, ULONG ealen)

	{

		OutputDebugString(L"Createfile");

		//ofstream fi("C:\\Users\\prath\\Desktop\\open.txt");

		//fi << "NtCreateFile";

		//fi.close();

		pid = GetCurrentProcessId();

		char const* p = reinterpret_cast<char const*>(objattr->ObjectName);

		string fname = p;

		if (fname.find("\\PhysicalDrive0") != string::npos)

		{

			ofstream f5("C:\\Program Files\\prath\\trigger.txt", ios::app | ios::out);

			f5 << pid << "\n";

			f5.close();

			ofstream f15("C:\\Program Files\\prath\\h.txt", ios::app | ios::out);

			ofstream* f = &f15;

			write2(pid,1,"Bootkit",f);

			f15.close();

		}

		return pOriginalNtCreateFile(fhand,dacc,objattr,iostatus,alloc_size,fileatrr,shareacc,createdispo,createopt,eabuf,ealen);

	}

	HANDLE FindFirstFileWHook(LPCWSTR fname, LPWIN32_FIND_DATAW fdata)

	{

		c5++;

		if (c5 > 20 && i6 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f14("C:\\Program Files\\prath\\g.txt", ios::app | ios::out);

			ofstream* f = &f14;

			write2(pid, c5, "FindFirst", f);

			f14.close();

			i6 = 1;

		}

		return pOriginalFindFirstFile(fname, fdata);

	}

	BOOL FindNextFileWHook(HANDLE hfile, LPWIN32_FIND_DATAW fdata)

	{

		c5++;

		if (c5 > 20 && i6 == 0)

		{

			pid = GetCurrentProcessId();

			ofstream f16("C:\\Program Files\\prath\\g.txt", ios::app | ios::out);

			ofstream* f = &f16;

			write2(pid, c5, "FindFirst", f);

			f16.close();

			i6 = 1;

		}

		return pOriginalFindNextFile(hfile, fdata);

	}

	MH_STATUS InitCustomizationHooks()

	{

		//MH_STATUS status1 = MH_CreateHook(CreateFileW, (void*)CreateFileWHook, (void**)&pOriginalCreateFileW);

		MH_STATUS status2 = MH_CreateHook(WriteFile, (void*)WriteFileHook, (void**)&pOriginalWriteFile);

		MH_STATUS status3 = MH_CreateHook(CryptEncrypt, (void*)CryptEncryptHook, (void**)&pOriginalCryptEncrypt);

		MH_STATUS status4 = MH_CreateHook(GetFileAttributesW, (void*)GetFileAttributesWHook, (void**)&pOriginalGetFileAttributesW);

		MH_STATUS status5 = MH_CreateHook(CryptAcquireContextW, (void*)CryptAcquireContextWHook, (void**)&pOriginalCryptAcquireContextW);

		MH_STATUS status6 = MH_CreateHook(BCryptEncrypt, (void*)BCryptEncryptHook, (void**)&pOriginalBCryptEncrypt);

		MH_STATUS status7 = MH_CreateHook(Process32FirstW, (void*)Process32FirstWHook, (void**)&pOriginalProcess32FirstW);

		MH_STATUS status8 = MH_CreateHook(Process32NextW, (void*)Process32NextWHook, (void**)&pOriginalProcess32NextW);

		MH_STATUS status9 = MH_CreateHook(CryptGenRandom, (void*)CryptGenRandomHook, (void**)&pOriginalCryptGenRandom);

		MH_STATUS status10 = MH_CreateHook(NtOpenFile, (void*)NtOpenFileHook, (void**)&pOriginalNtOpenFile);

		MH_STATUS status11 = MH_CreateHook(GetFileAttributesExW, (void*)GetFileAttributesExWHook, (void**)&pOriginalGetFileAttrib);

		//MH_STATUS status12 = MH_CreateHook(FindFirstFileExW, (void*)FindFirstFileHook, (void**)&pOriginalFindFirst);

		MH_STATUS status13 = MH_CreateHook(NtCreateFile, (void*)NtCreateFileHook, (void**)&pOriginalNtCreateFile);

		MH_STATUS status14 = MH_CreateHook(FindFirstFileW, (void*)FindFirstFileWHook, (void**)&pOriginalFindFirstFile);

		MH_STATUS status15 = MH_CreateHook(FindNextFileW, (void*)FindNextFileWHook, (void**)&pOriginalFindNextFile);

		/*if (status1 == MH_OK)

		{

			status1 = MH_QueueEnableHook(CreateFileW);

		}*/

		if (status2 == MH_OK) {

			status2 = MH_QueueEnableHook(WriteFile);

		}

		if (status3 == MH_OK) {

			OutputDebugString(L"CryptEnOk");

			status3 = MH_QueueEnableHook(CryptEncrypt);

		}

		if (status4 == MH_OK) {

			status4 = MH_QueueEnableHook(GetFileAttributesW);

		}

		if (status5 == MH_OK) {

			status5 = MH_QueueEnableHook(CryptAcquireContextW);

		}

		if (status6 == MH_OK) {

			OutputDebugString(L"BCryptEnOk");

			status6 = MH_QueueEnableHook(BCryptEncrypt);

		}

		if (status7 == MH_OK) {

			status7 = MH_QueueEnableHook(Process32FirstW);

		}

		if (status8 == MH_OK) {

			status8 = MH_QueueEnableHook(Process32NextW);

		}

		if (status9 == MH_OK) {

			status9 = MH_QueueEnableHook(CryptGenRandom);

		}

		if (status10 == MH_OK) {

			OutputDebugString(L"OpenFileOk");

			status10 = MH_QueueEnableHook(NtOpenFile);

		}

		if (status11 == MH_OK) {

			status11 = MH_QueueEnableHook(GetFileAttributesExW);

		}

		/*if (status12 == MH_OK) {

			//status12 = MH_QueueEnableHook(FindFirstFileExW);

		}*/

		if (status13 == MH_OK) {

			OutputDebugString(L"CreateFileOk");

			status13 = MH_QueueEnableHook(NtCreateFile);

		}

		if (status14 == MH_OK) {

			//status14 = MH_QueueEnableHook(FindFirstFileW);

		}

		if (status15 == MH_OK) {

			status15 = MH_QueueEnableHook(FindNextFileW);

		}

		return status2;

	}

}

bool CustomizationSession::Start(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept

{

	auto instance = new (std::nothrow) CustomizationSession();

	if (!instance) {

		LOG(L"Allocation of CustomizationSession failed");

		return false;

	}

	if (!instance->StartAllocated(runningFromAPC, sessionManagerProcess, sessionMutex)) {

		delete instance;

		return false;

	}

	// Instance will free itself.

	return true;

}

bool CustomizationSession::StartAllocated(bool runningFromAPC, HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept

{

	// Create the session semaphore. This will block the library if another instance

	// (from another session manager process) is already injected and its customization session is active.

	WCHAR szSemaphoreName[sizeof("CustomizationSessionSemaphore-pid=1234567890")];

	swprintf_s(szSemaphoreName, L"CustomizationSessionSemaphore-pid=%u", GetCurrentProcessId());

	HRESULT hr = m_sessionSemaphore.create(1, 1, szSemaphoreName);

	if (FAILED(hr)) {

		LOG(L"Semaphore creation failed with error %08X", hr);

		return false;

	}

	m_sessionSemaphoreLock = m_sessionSemaphore.acquire();

	if (WaitForSingleObject(sessionManagerProcess, 0) != WAIT_TIMEOUT) {

		VERBOSE(L"Session manager process is no longer running");

		return false;

	}

	if (!InitSession(runningFromAPC, sessionManagerProcess)) {

		return false;

	}

	if (runningFromAPC) {

		// Create a new thread for us to allow the program's main thread to run.

		try {

			// Note: Before creating the thread, the CRT/STL bumps the

			// reference count of the module, something a plain CreateThread

			// doesn't do.

			std::thread thread(&CustomizationSession::RunAndDeleteThis, this,

				sessionManagerProcess, sessionMutex);

			thread.detach();

		}

		catch (const std::exception& e) {

			LOG(L"%S", e.what());

			UninitSession();

			return false;

		}

	}

	else {

		// No need to create a new thread, a dedicated thread was created for us

		// before injection.

		RunAndDeleteThis(sessionManagerProcess, sessionMutex);

	}

	return true;

}

bool CustomizationSession::InitSession(bool runningFromAPC, HANDLE sessionManagerProcess) noexcept

{

	MH_STATUS status = MH_Initialize();

	if (status != MH_OK) {

		LOG(L"MH_Initialize failed with %d", status);

		return false;

	}

	if (runningFromAPC) {

		// No other threads should be running, skip thread freeze.

		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_NONE_UNSAFE);

	}

	else {

		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);

	}

	try {

		m_newProcessInjector.emplace(sessionManagerProcess);

	}

	catch (const std::exception& e) {

		LOG(L"InitSession failed: %S", e.what());

		m_newProcessInjector.reset();

		MH_Uninitialize();

		return false;

	}

	status = InitCustomizationHooks();

	if (status != MH_OK) {

		LOG(L"InitCustomizationHooks failed with %d", status);

	}

	status = MH_ApplyQueued();

	if (status != MH_OK) {

		LOG(L"MH_ApplyQueued failed with %d", status);

	}

	if (runningFromAPC) {

		MH_SetThreadFreezeMethod(MH_FREEZE_METHOD_FAST_UNDOCUMENTED);

	}

	return true;

}

void CustomizationSession::RunAndDeleteThis(HANDLE sessionManagerProcess, HANDLE sessionMutex) noexcept

{

	m_sessionManagerProcess.reset(sessionManagerProcess);

	if (sessionMutex) {

		m_sessionMutex.reset(sessionMutex);

	}

	// Prevent the system from displaying the critical-error-handler message box.

	// A message box like this was appearing while trying to load a dll in a

	// process with the ProcessSignaturePolicy mitigation, and it looked like this:

	// https://stackoverflow.com/q/38367847

	DWORD dwOldMode;

	SetThreadErrorMode(SEM_FAILCRITICALERRORS, &dwOldMode);

	Run();

	SetThreadErrorMode(dwOldMode, nullptr);

	delete this;

}

void CustomizationSession::Run() noexcept

{

	DWORD waitResult = WaitForSingleObject(m_sessionManagerProcess.get(), INFINITE);

	if (waitResult != WAIT_OBJECT_0) {

		LOG(L"WaitForSingleObject returned %u, last error %u", waitResult, GetLastError());

	}

	VERBOSE(L"Uninitializing and freeing library");

	UninitSession();

}

void CustomizationSession::UninitSession() noexcept

{

	MH_STATUS status = MH_Uninitialize();

	if (status != MH_OK) {

		LOG(L"MH_Uninitialize failed with status %d", status);

	}

	m_newProcessInjector.reset();

}
