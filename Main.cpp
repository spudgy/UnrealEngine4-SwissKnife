#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#include "stdafx.h"

//#define UE3

#include "client_ws.hpp"
#include "server_ws.hpp"
#include <Windows.h>
#include <thread>
#include "sol2.hpp"
#include "json.hpp"

#pragma comment(lib,"libcryptoMT.lib")
#pragma comment(lib,"Crypt32.lib")
#pragma comment(lib,"LuaJIT/lib64/Release/LuaJIT.lib")

using json = nlohmann::json;
using WsServer = SimpleWeb::SocketServer<SimpleWeb::WS>;

WsServer server;
std::vector<std::shared_ptr<WsServer::Connection>> vConnects;
std::unique_ptr<sol::state> state;
#define lua (*state)

ULONG_PTR ENGINE_OFFSET = 0;

#define DRV_MODE
#ifdef DRV_MODE
/* TODO */
#include "Driver.hpp"
#endif

#pragma region Memory
#include <string>

#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>
static std::vector<uint64_t> GetProcessIdsByName(std::string name)
{
	std::vector<uint64_t> res;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!snap) throw std::exception("CreateToolhelp32Snapshot failed");
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(entry);
	if (!Process32First(snap, &entry)) throw std::exception("Process32First failed");
	do
	{
		if (entry.szExeFile == (name))
		{
			res.push_back(entry.th32ProcessID);
		}
	} while (Process32Next(snap, &entry));
	CloseHandle(snap);
	return res;
}
std::wstring sWndFind = L"";
HWND GetPUBGWindowProcessId(__out LPDWORD lpdwProcessId)
{
	HWND  hWnd = FindWindowW(NULL, sWndFind.c_str());
	//wprintf(L"hwnd %p / %s\n", hWnd,sWndFind.c_str());
	if (hWnd == NULL) {
		hWnd = FindWindowW(L"UnrealWindow", NULL);

	}

	if (hWnd != NULL)
	{
		if (!GetWindowThreadProcessId(hWnd, lpdwProcessId))
			return NULL;
	}
	else {

	}
	return hWnd;
}
HMODULE GetModuleBaseAddress(HANDLE handle) {
	HMODULE hMods[1024];
	DWORD   cbNeeded;

	if (EnumProcessModules(handle, hMods, sizeof(hMods), &cbNeeded)) {
		return hMods[0];
	}
	return NULL;
}
BOOL WINAPI WriteProcessMemoryCallback(_In_ HANDLE hProcess, _In_ LPVOID lpBaseAddress, LPVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesRead)
{
#ifdef DRV_MODE
	drv.Write(hProcess, (ULONG_PTR)lpBaseAddress, lpBuffer, nSize);
	return true;
#endif

	return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}
BOOL WINAPI ReadProcessMemoryCallback(_In_ HANDLE hProcess, _In_ LPCVOID lpBaseAddress, LPVOID lpBuffer, _In_ SIZE_T nSize, _Out_opt_ SIZE_T* lpNumberOfBytesRead)
{
#ifdef DRV_MODE
	drv.Read(hProcess, (ULONG_PTR)lpBaseAddress, lpBuffer, nSize);
	return true;
#endif
	return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

HANDLE hProcess = 0;
ULONG_PTR base = 0;
ULONG_PTR GetBase() {

	if (base == 0) {
		DWORD procId;
		if (!GetPUBGWindowProcessId(&procId)) {
			return 0;
		}

#ifdef DRV_MODE
		hProcess = (HANDLE)procId;
		base = drv.GetModule(procId);
#else
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
		base = (ULONG_PTR)GetModuleBaseAddress(hProcess);
#endif
		DWORD64 bBase = 0;
		ReadProcessMemoryCallback(hProcess, (LPCVOID)base, &bBase, 8, NULL);
		printf("%i Process Base: %p / %p\n",procId, base,bBase);
	}
	else if (hProcess) {
		DWORD nExit;
		if (GetExitCodeProcess(hProcess, &nExit) && nExit != STILL_ACTIVE) {
			base = 0;
			hProcess = 0;
		}
	}
	return base;
}

bool IsBadReadPtrEx(void* p)
{
	MEMORY_BASIC_INFORMATION mbi = { 0 };


#ifdef DRV_MODE
	if (drv.Query((HANDLE)hProcess, (ULONG_PTR)p, &mbi))
#else
	if (::VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi)))
#endif
	{
		DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
		bool b = !(mbi.Protect & mask);
		if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

		return b;
	}
	return true;
}

template <class T = LPVOID>
bool Write(LPVOID ptr, T val) {
	WriteProcessMemoryCallback(hProcess, ptr, &val, sizeof(T), NULL);
	return true;
}
template <class T = ULONG_PTR>
bool Write(ULONG_PTR ptr, T val) {
	WriteProcessMemoryCallback(hProcess, (LPVOID)ptr, &val, sizeof(T), NULL);
	return true;
}
template <class T = LPVOID>
T Read(LPVOID ptr) {
	T out = T();
	ReadProcessMemoryCallback(hProcess, ptr, &out, sizeof(T), NULL);
	return out;
}
template <class T = ULONG_PTR>
T Read(ULONG_PTR ptr) {
	T out = T();
	ReadProcessMemoryCallback(hProcess, (LPVOID)ptr, &out, sizeof(T), NULL);
	return out;
}
template <class T>
void ReadTo(LPVOID ptr, T* out, int len) {
	*out = T();
	ReadProcessMemoryCallback(hProcess, ptr, out, len, NULL);
}
#pragma endregion Memory

#pragma region UE4

std::function<const char* (DWORD)> getNameFnc;

LPBYTE GNames = 0;
std::map<int, std::string> nameMap;
DWORD NAME_CHUNK = 0x4000;


DWORD64 fNamePool = 0;
const char* GetNameFromFName(int key)
{
	DWORD chunkOffset = ((int)(key) >> 16); // Block
	WORD nameOffset = key;

	//if (chunkOffset > Read<DWORD>(fNamePool + 8)) return "BAD";//bad block?

	printf("%i chunk %i / %i \n",key, chunkOffset,nameOffset);
	// The first chunk/shard starts at 0x10, so even if chunkOffset is zero, we will start there.
	auto namePoolChunk = Read(fNamePool + ((chunkOffset + 2) * 8));
	auto entryOffset = namePoolChunk + (DWORD)(2 * nameOffset);
	WORD nameLength = Read<WORD>(entryOffset) >> 16;
	//printf("len: %i / %i / %p / %p - ", nLen,nameLength, entryOffset, namePoolChunk);
	if (nameLength > 256)nameLength = 255;
	static char cBuf[256];
	ReadTo((LPBYTE)entryOffset + 2, cBuf, nameLength);
	cBuf[nameLength] = 0;
	//printf("ret %s\n", cBuf);
	return cBuf;
}

class CNames {
public:
	static const char* GetName(int id) {
		if (nameMap[id].empty()) {
			nameMap[id] = GetNameS(id);
		}
		return nameMap[id].c_str();
	}
	static const char* GetNameS(int id) {
		if (getNameFnc) return getNameFnc(id);
		if (fNamePool) return GetNameFromFName(id);
		static char m_name[124];
		char msg[124];
		auto ptr = GNames;
		auto pData = Read<ULONG_PTR>((PBYTE)ptr + ((id / NAME_CHUNK) * sizeof(ULONG_PTR)));

		LPBYTE pEntry = Read<LPBYTE>((LPVOID)((ULONG_PTR)(pData + (id % NAME_CHUNK) * sizeof(ULONG_PTR))));
		ZeroMemory(m_name, sizeof(m_name));
		ReadTo((LPVOID)&pEntry[0x10], m_name, sizeof(m_name) - 2);
		return m_name;
	}
};
std::function<int(ULONG_PTR)> getIdFnc;
std::function<ULONG_PTR(ULONG_PTR)> getClassFnc;
std::function<ULONG_PTR(ULONG_PTR)> getOuterClassFnc;
std::function<ULONG_PTR(ULONG_PTR)> getEncObjFnc;
std::function<ULONG_PTR(ULONG_PTR)> getActorsFnc;

#include "UE4Core.hpp"

template<class T>
class UProxy {
public:
	ULONG_PTR ptr;
	T obj;
	UProxy() {
		ptr = 0;
	}
	bool operator ==(UProxy &other) {
		return ptr == other.ptr;
	}
	UProxy(ULONG_PTR _ptr) : ptr(_ptr) {
		ReadTo((LPBYTE)_ptr, &obj, sizeof(obj));
	}
	T* GetObject() {
		return &obj;
	}
	DWORD GetId() {
		if (getIdFnc) return getIdFnc(ptr);

		return Read<DWORD>(ptr + UObj_Offsets::dwNameIdOffset);
		//return obj.Name.Index;
	}
	std::string GetName() {
		auto n = CNames::GetName(GetId());
		auto slash = strrchr(n, '/');
		if (slash)
			return slash + 1;
		return n;
	}
	bool IsA(UClass* pClass)
	{
		/*for (UClass* SuperClass = this->Class; SuperClass; SuperClass = (UClass*)SuperClass->SuperField)
		{
		if (SuperClass == pClass)
		return true;
		}*/

		return false;
	}
	template <class T>
	T As() {
		return T(ptr);
	}
	UProxy GetClass() {
		if (getClassFnc) return UProxy(getClassFnc(ptr));
		return UProxy(Read(ptr + UObj_Offsets::dwClassOffset));
	}
	bool HasOuter() {
		return obj.Outer != NULL;
	}
	UProxy GetOuter() {
		if (getOuterClassFnc) return UProxy(getOuterClassFnc(ptr));

		return UProxy((ULONG_PTR)obj.Outer);
	}
	virtual bool Is(std::string name) {

		return GetClass().GetName() == name;
	}
	bool IsMulticastDelegate() { return Is("MulticastDelegateProperty"); }
	bool IsFunction() { return Is("Function") || Is("ScriptStruct") || Is("DelegateFunction") ||
		Is("Enum") || Is("Const") //ue3 support
		; }
	bool IsStruct() { return Is("StructProperty"); }
	bool IsFloat() { return Is("FloatProperty"); }
	bool IsBool() { return Is("BoolProperty"); }
	bool IsName() { return Is("NameProperty"); }
	bool IsByte() { return Is("ByteProperty"); }
	bool IsWeakObject() { return Is("WeakObjectProperty"); }
	bool IsObject() { return Is("ObjectProperty") || IsWeakObject() ||
		Is("ComponentProperty")//ue3 support
		; }
	bool IsInt() { return Is("IntProperty"); }
	bool IsInt8() { return Is("Int8Property"); }
	bool IsUIn32() { return Is("UInt32Property"); }
	bool IsUInt64() { return Is("UInt64Property"); }
	bool IsClass() { return Is("ClassProperty") || Is("Class"); }
	bool IsArray() { return Is("ArrayProperty"); }
	bool IsMap() { return Is("MapProperty"); }
	bool IsString() { return Is("StrProperty"); }
	bool IsField() { return Is("Field"); }
	bool IsWidget() { return Is("UserWidget"); }
	bool IsProperty() { return Is("Property") || IsArray() || IsInt() || IsObject() || IsWeakObject() || IsByte() || IsName() || IsBool() || IsFloat(); }
	bool IsPackage() {
		return Is("Package");
	}
	bool IsIgnore() {
		return (strstr(GetName().c_str(), "Default__") && !strstr(GetName().c_str(), "Engine")) || IsPackage() || IsClass() || IsFunction() || IsStruct() || IsProperty() || IsWidget();
	}
	const char* GetFullName()
	{
		if (obj.Class && obj.Outer)
		{
			static char cOutBuffer[512];

			char cTmpBuffer[512];

			strcpy_s(cOutBuffer, this->GetName().c_str());

			for (UProxy pOuter = this->GetOuter(); 1; pOuter = pOuter.GetOuter())
			{
				strcpy_s(cTmpBuffer, pOuter.GetName().c_str());
				strcat_s(cTmpBuffer, ".");

				size_t len1 = strlen(cTmpBuffer);
				size_t len2 = strlen(cOutBuffer);

				memmove(cOutBuffer + len1, cOutBuffer, len1 + len2 + 1);
				memcpy(cOutBuffer, cTmpBuffer, len1);
				if (!pOuter.HasOuter())
					break;
			}

			strcpy_s(cTmpBuffer, this->GetClass().GetName().c_str());
			strcat_s(cTmpBuffer, " ");

			size_t len1 = strlen(cTmpBuffer);
			size_t len2 = strlen(cOutBuffer);

			memmove(cOutBuffer + len1, cOutBuffer, len1 + len2 + 1);
			memcpy(cOutBuffer, cTmpBuffer, len1);

			return cOutBuffer;
		}

		return "(null)";
	}
	bool HasChildren() {
		return GetChildren().ptr != NULL;
	}
	UProxy GetChildren(bool bStruct = false) {
		if (UObj_Offsets::dwChildOffset) return UProxy(Read<ULONG_PTR>((LPBYTE)ptr + (bStruct ? UObj_Offsets::dwStructOffset : UObj_Offsets::dwChildOffset)));
		return Read<ULONG_PTR>((LPBYTE)ptr + offsetof(UStruct, Children));;
	}
};
class UFieldProxy : public UProxy<UField> {
public:
	UFieldProxy() : UProxy<UField>() {

	}
	UFieldProxy(ULONG_PTR _ptr) : UProxy<UField>(_ptr) {

	}
};
class UPropertyProxy : public UProxy<UProperty> {
public:
	UPropertyProxy() : UProxy<UProperty>() {
	}
	UPropertyProxy(ULONG_PTR _ptr) : UProxy<UProperty>(_ptr) {

	}
	bool HasNext() {
		auto pNext = GetNext().ptr;
		return pNext != NULL && (ULONG_PTR)pNext != 0xCCCCCCCCCCCCCCCC && (ULONG_PTR)pNext != 0;
	}
	UPropertyProxy GetNext() {
		return Read<ULONG_PTR>((LPBYTE)ptr + UObj_Offsets::dwNextOffset);
		return UPropertyProxy((ULONG_PTR)obj.Next);
	}
	int GetOffset() {
		return Read<DWORD>(ptr + UObj_Offsets::dwOffOffset);
		return obj.Offset;
	}
	DWORD GetBitMask() {
#ifdef UE3
		if (UObj_Offsets::dwBitmaskOffset) return Read<DWORD>((LPBYTE)ptr + UObj_Offsets::dwBitmaskOffset);
#else
		if (UObj_Offsets::dwBitmaskOffset) return Read<WORD>((LPBYTE)ptr + UObj_Offsets::dwBitmaskOffset);
#endif
		return Read<WORD>((LPBYTE)ptr + offsetof(UBoolProperty, BitMask) + 2);
	}
	UPropertyProxy GetInner() {
		if (UObj_Offsets::dwInnerOffset) return UPropertyProxy(Read<ULONG_PTR>((LPBYTE)ptr + UObj_Offsets::dwInnerOffset));
		return UPropertyProxy(Read<ULONG_PTR>((LPBYTE)ptr + offsetof(UArrayProperty, Inner)));
	}
	UPropertyProxy GetKey() {
		return UPropertyProxy(Read<ULONG_PTR>((LPBYTE)ptr + offsetof(UMapProperty, KeyProp)));
	}
	UPropertyProxy GetValue() {
		return UPropertyProxy(Read<ULONG_PTR>((LPBYTE)ptr + offsetof(UMapProperty, ValueProp)));
	}
	UProxy GetStruct() {
		if (UObj_Offsets::dwInnerOffset) return UProxy(Read<ULONG_PTR>((LPBYTE)ptr + UObj_Offsets::dwInnerOffset));
		return UProxy(Read<ULONG_PTR>((LPBYTE)ptr + offsetof(UStructProperty, Struct)));
	}
	int GetArrayDim() {
		if (UObj_Offsets::dwSizeOffset)return Read<int>((LPBYTE)ptr + UObj_Offsets::dwSizeOffset);
		return obj.ArrayDim;
	}
	int GetElementSize() {
		if (UObj_Offsets::dwSizeOffset)return Read<int>((LPBYTE)ptr + UObj_Offsets::dwSizeOffset + 4);
		return obj.ElementSize;
	}
	int GetSize() {
		return GetArrayDim() * GetElementSize();
	}
};
class UClassProxy : public UProxy<UClass> {
public:
	UClassProxy() : UProxy<UClass>() {

	}
	UClassProxy(ULONG_PTR _ptr) : UProxy<UClass>(_ptr) {

	}
	int GetSize() {
		if (UObj_Offsets::dwPropSize) return Read<int>((LPBYTE)ptr + UObj_Offsets::dwPropSize);
		return obj.PropertySize;
	}
	bool HasSuperClass() {
		return GetSuperClass().ptr != NULL;
	}
	UClassProxy GetSuperClass() {
		if (UObj_Offsets::dwSuperClassOffset2) return Read<ULONG_PTR>((LPBYTE)ptr + UObj_Offsets::dwSuperClassOffset2);
		return UClassProxy((ULONG_PTR)obj.SuperField);
	}
	std::string GetFullClass() {
		std::string str;

		auto c = *this;
		while (c.HasSuperClass()) {
			std::string className = c.GetName();
			if (className.empty())
				break;
			str.append(".").append(className);
			c = c.GetSuperClass();
		}
		return str;
	}
	virtual bool Is(std::string name) {
		auto c = *this;
		while (c.HasSuperClass()) {
			if (c.GetName() == name)
				return true;
			c = c.GetSuperClass();
		}
		return c.GetName() == name;
	}
};
class UObjectProxy : public UProxy<UObject> {
public:
	UObjectProxy(ULONG_PTR _ptr) : UProxy<UObject>(_ptr) {

	}
	virtual bool Is(std::string name) {
		return GetClass().Is(name);
	}
};


bool FindSignature(LPBYTE ptr, int nsize, char* sign, UINT nLen) {
	for (DWORD i = 0; i < nsize; i++) {
		int j = 0;
		while (ptr[i + j] == (BYTE)sign[j]) {
			j++;
			if (j == nLen) {
				return true;
			}
		}
	}
	return false;
}

ULONG_PTR gObj = 0;
void GScan() {
	MEMORY_BASIC_INFORMATION meminfo = { 0 };
	ULONG_PTR current = 0x10000;
	//FUObjectArray GObj{};
	int counter = 0;
	char msg[124];
#ifdef DRV_MODE
	while (drv.Query((HANDLE)hProcess, current, &meminfo) && current < GetBase())
#else
	while (VirtualQueryEx(hProcess, (PVOID)current, &meminfo, 48) && current < GetBase())
#endif
	{
		if (meminfo.Protect & PAGE_NOACCESS)
		{
			current += meminfo.RegionSize;
			continue;
		}
		if (meminfo.State == MEM_COMMIT && (meminfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
		{
			
			if (meminfo.RegionSize == 0x10000 && !GNames)
			{
				char* bMem = (char*)malloc(0x10000);
				ReadTo(meminfo.BaseAddress, bMem, 0x10000);

				const wchar_t* sign = L"On engine startup";
				const wchar_t* sign2 = L"Defines the memory";
				if (Read<ULONG_PTR>((PCHAR)meminfo.BaseAddress + 0x80) != 0 && FindSignature((LPBYTE)bMem, 0x10000, (char*)sign, wcslen(sign))) {
					LPBYTE lpMem = Read<LPBYTE>(Read<LPBYTE>((PCHAR)meminfo.BaseAddress + 0x80)) + 0x10;
					char bMem[24];
					ReadTo(lpMem, bMem, 24);
					OutputDebugStringA(bMem);
					if (!strcmp(bMem, "None")) {
						OutputDebugStringA("REALLY FOUND!!!!!\n");
						GNames = (LPBYTE)((PCHAR)meminfo.BaseAddress + 0x80);
					}
					else {
						lpMem = Read<LPBYTE>(Read<LPBYTE>((PCHAR)meminfo.BaseAddress + 0x510)) + 0x10;
						ReadTo(lpMem, bMem, 24);
						OutputDebugStringA(bMem);
						if (!strcmp(bMem, "None")) {
							OutputDebugStringA("REALLY FOUND2!!!!!\n");
							GNames = (LPBYTE)((PCHAR)meminfo.BaseAddress + 0x510);
						}
					}
				}
				else if (Read<ULONG_PTR>((PCHAR)meminfo.BaseAddress + 0x10) != 0 && FindSignature((LPBYTE)bMem, 0x10000, (char*)sign2, wcslen(sign2))) {
					//check if points to "None"
					LPBYTE lpMem = Read<LPBYTE>(Read<LPBYTE>((PCHAR)meminfo.BaseAddress + 0x10)) + 0x10;
					char bMem[24];
					ReadTo(lpMem, bMem, 24);
					OutputDebugStringA(bMem);
					if (!strcmp(bMem, "None")) {
						OutputDebugStringA("REALLY FOUND!!!!!\n");
						GNames = (LPBYTE)((PCHAR)meminfo.BaseAddress + 0x10);
					}
				}
				free(bMem);
				//}
			}
		}
		current += meminfo.RegionSize;
	}
	//GetGObjectsGen();

	//gObj = (ULONG_PTR)GObj.ObjObjects.Objects;
	ULONG_PTR pGObj = 0;
	//sprintf_s(msg, 124, "GObj PTR: %p \n", GetGObjects());
	//OutputDebugStringA(msg);
	for (DWORD i = 0; i < 10; i++) {
		OutputDebugStringA(CNames::GetName(i));
		OutputDebugStringA("\n");
	}
	//sprintf_s(msg, 124, "SCAN GObj PTR: %p \n", gObj);
	//OutputDebugStringA(msg);
	sprintf_s(msg, 124, "SCAN GNames PTR: %p / %p / %p \n", GNames, GNames - GetBase(), GetBase());
	OutputDebugStringA(msg);
}
#pragma endregion UE4


#pragma region UE4Parser
#include <locale>
#include <codecvt>
std::string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}
struct BIT_CHECK {
	bool b1 : 1;
	bool b2 : 1;
	bool b3 : 1;
	bool b4 : 1;
	bool b5 : 1;
	bool b6 : 1;
	bool b7 : 1;
	bool b8 : 1;
};
DWORD SetBitState(ULONG_PTR dwOffset, DWORD dwBitmask, bool bState) {
#ifdef UE3
	DWORD stateRet = Read<DWORD>((LPBYTE)dwOffset);
	return bState ? stateRet | dwBitmask : stateRet & ~dwBitmask;
#endif
	BYTE b = Read<BYTE>((LPBYTE)dwOffset);
	if (dwBitmask == 0xFF01)
		return bState;
	BIT_CHECK* bc = (BIT_CHECK*)&b;
	switch (dwBitmask) {
	case 0x0101:
		bc->b1 = bState;
		break;
	case 0x0202:
		bc->b2 = bState;
		break;
	case 0x0404:
		bc->b3 = bState;
		break;
	case 0x0808:
		bc->b4 = bState;
		break;
	case 0x1010:
		bc->b5 = bState;
		break;
	case 0x2020:
		bc->b6 = bState;
		break;
	case 0x4040:
		bc->b7 = bState;
		break;
	case 0x8080:
		bc->b8 = bState;
		break;
	}
	return b;
}
bool GetBitState(ULONG_PTR dwOffset, DWORD dwBitmask) {
#ifdef UE3
	return  Read<DWORD>((LPBYTE)dwOffset) & dwBitmask;
#endif
	BYTE b = Read<BYTE>((LPBYTE)dwOffset);
	if (dwBitmask == 0xFF01)
		return b;
	BIT_CHECK* bc = (BIT_CHECK*)&b;
	bool bRet = false;
	switch (dwBitmask) {
	case 0x0101:
		bRet = bc->b1;
		break;
	case 0x0202:
		bRet = bc->b2;
		break;
	case 0x0404:
		bRet = bc->b3;
		break;
	case 0x0808:
		bRet = bc->b4;
		break;
	case 0x1010:
		bRet = bc->b5;
		break;
	case 0x2020:
		bRet = bc->b6;
		break;
	case 0x4040:
		bRet = bc->b7;
		break;
	case 0x8080:
		bRet = bc->b8;
		break;
	}
	return bRet;
}

DWORD_PTR Decrypt_RootComponent(__int64 v3)
{
	return v3;
}
std::string GetObjectValue(ULONG_PTR pObj, UPropertyProxy* pProperty, ULONG_PTR dwOffset, ULONG_PTR& lParam, bool bZOMG = false) {
	static char szBuf[1024];
	if (dwOffset == -1) { //get from prop
						  //dwOffset = pProperty->Offset;
	}
	dwOffset += pObj;
	if (pProperty->IsByte()) { sprintf_s(szBuf, 124, "%i", Read<BYTE>((LPBYTE)dwOffset)); return szBuf; }
	else if (pProperty->IsInt()) { sprintf_s(szBuf, 124, "%i", Read<int>((LPBYTE)dwOffset)); return szBuf; }
	else if (pProperty->IsInt8()) { sprintf_s(szBuf, 124, "%i", Read<char>((LPBYTE)dwOffset)); return szBuf; }
	else if (pProperty->IsUIn32()) { sprintf_s(szBuf, 124, "%i", Read<DWORD>((LPBYTE)dwOffset)); return szBuf; }
	else if (pProperty->IsUInt64()) { sprintf_s(szBuf, 124, "%Ii", Read<DWORD64>((LPBYTE)dwOffset)); return szBuf; }
	else if (pProperty->IsFloat()) { sprintf_s(szBuf, 124, "%f", Read<float>((LPBYTE)dwOffset)); return szBuf; }
	else if (pProperty->IsBool()) {
		lParam = pProperty->GetBitMask(); 

#ifdef UE3
		bool bState = Read<DWORD>(dwOffset) & pProperty->GetBitMask();
#else
		bool bState = GetBitState(dwOffset, pProperty->GetBitMask());
#endif
		sprintf_s(szBuf, 124, "%s", bState ? "true" : "false");
		return szBuf;
	}

	else if (pProperty->IsObject()) {
		UObjectProxy p(Read<ULONG_PTR>((LPBYTE)dwOffset));
		lParam = p.ptr;
		if (!p.ptr) return "NULL";
		sprintf_s(szBuf, 124, "%s* [%p]", p.GetName().c_str(), (LPBYTE)p.ptr);
		return szBuf;
	}
	else if (pProperty->IsName()) {

		auto fData = CNames::GetName(Read<DWORD>((LPBYTE)dwOffset));
		strcpy_s(szBuf, 124, (std::string("FName ") + std::string(fData)).c_str());
		return szBuf;
	}
	else if (pProperty->IsClass()) {
		UClassProxy p(Read<ULONG_PTR>((LPBYTE)dwOffset));
		lParam = p.ptr;
		sprintf_s(szBuf, 124, "UClass *%s", p.GetName().c_str());
		return szBuf;
	}
	else if (pProperty->IsString()) {
		FString buf = Read<FString>((LPBYTE)dwOffset);
		if (buf.Count == 0) return "\"\"";
		std::wstring sArray;
		sArray += '"';
		for (int i = 0; i < buf.Count - 1; i++) {
			wchar_t wchar = Read<wchar_t>((LPBYTE)buf.Data + (i * 2));
			sArray += wchar;
		}
		sArray += '"';
		if (sArray.size() > 1024) sArray = sArray.substr(0, 1024);
		return ws2s(sArray);
	}
	else if (pProperty->IsMulticastDelegate()) {
		return "ScriptDeletage";
	}
	else if (pProperty->IsArray()) {
		TArray<ULONG_PTR> buf = Read<TArray<ULONG_PTR>>((LPBYTE)dwOffset);
		std::string sPropertyTypeInner = pProperty->GetInner().GetName();
		std::string sArray;
		for (int i = 0; i < buf.Count; i++) {
			ULONG_PTR ptr = Read<ULONG_PTR>((LPBYTE)buf.Data + (i * 8));
			if (i == 0) {
				lParam = ptr;
			}
			char szPtr[32];
			sprintf_s(szPtr, 32, "%p", (LPBYTE)ptr);
			sArray += szPtr + std::string(",");
			if (i > 30) {
				sArray.append(",...");
				break;
			}
		}
		sprintf_s(szBuf, 1024, "TArray<%s>(%i)", sPropertyTypeInner.c_str(), buf.Count);
		std::string sRet = szBuf;
		sRet.append("{").append(sArray).append("}");
		return sRet;
	}
	else if (pProperty->IsMap()) {
		sprintf_s(szBuf, 124, "TMap< %s , %s >", pProperty->GetKey().GetName().c_str(), pProperty->GetValue().GetName().c_str());
		return szBuf;
	}
	else if (pProperty->Is("EncryptedObjectProperty")) {
		auto r = Decrypt_RootComponent(Read<ULONG_PTR>(dwOffset));
		lParam = r;
		UObjectProxy p(r);
		if (!p.ptr) return "NULL ENC";
		sprintf_s(szBuf, 124, "ENC %s* [%p]", p.GetName().c_str(), (LPBYTE)p.ptr);
		return szBuf;
	}
	else if (pProperty->Is("TextProperty")) {
		LPBYTE pPtr = Read<LPBYTE>((LPBYTE)dwOffset + 8);
		if (Read<LPBYTE>(pPtr + 0x18) == Read<LPBYTE>(pPtr + 0x20) + 0x10) {
			wchar_t wName[256];
			ReadTo(Read<LPBYTE>(Read<LPBYTE>(Read<LPBYTE>((LPBYTE)dwOffset + 8) + 0x18)), wName, 256 * 2);
			wName[255] = 0;
			sprintf_s(szBuf, 256, "TEXTPROP [%s]", ws2s(wName).c_str());
		}
		else {
			wchar_t wName[256];
			ReadTo(Read<LPBYTE>(Read<LPBYTE>((LPBYTE)dwOffset) + 0x38), wName, 256 * 2);
			sprintf_s(szBuf, 256, "TEXTPROP %p [%p]", Read<LPBYTE>((LPBYTE)dwOffset), dwOffset);
		}
		return szBuf;

	}
	return std::string("Unknown ").append(pProperty->GetFullName());
}
std::string GetHex(int val) {
	char msg[124];
	sprintf_s(msg, 124, "%x", val);
	return msg;
}

bool SortProperty(UPropertyProxy& pPropertyA, UPropertyProxy& pPropertyB) {
	if (pPropertyA.GetOffset() == pPropertyB.GetOffset()
		&& pPropertyA.IsBool() && pPropertyB.IsBool()) {
		return pPropertyA.GetBitMask() < pPropertyB.GetBitMask();
	}
	return (pPropertyA.GetOffset() < pPropertyB.GetOffset());
}
std::vector< UPropertyProxy> GetProps(UClassProxy c,DWORD& structSize) {
	structSize = 0;
	//..
	//check class
	std::vector< UPropertyProxy> vProperty;
	//find structure and dump it here..
	structSize = c.GetSize();
	while (c.HasSuperClass()) {
		//check if no props
		if (c.GetSuperClass().GetSize() == c.GetSize()) {
			OutputDebugStringA("NO PROPS!");
			c = c.GetSuperClass();
			continue;
		}

		//print size
		std::string className = c.GetName();
		printf("class: %p / %s\n", c.ptr, className.c_str());
		OutputDebugStringA(className.c_str());
		if (!c.HasChildren()) {
			c = c.GetSuperClass();
			continue;
		}
		//list properties
		UPropertyProxy f = c.GetChildren().As<UPropertyProxy>();
		while (1) {
			//char msg[1024];
			//sprintf_s(msg, 1024, "%p / %s\n",f.ptr,f.GetName().c_str());
			//OutputDebugStringA(msg);
			//OutputDebugStringA("\n");
			if (!f.IsFunction()) {
				vProperty.push_back(f);
			}
			if (!f.HasNext()) {
				break;
			}

			auto _f = f.GetNext();
			if (_f.ptr == f.ptr || _f.GetId() == 0)
				break;
			f = _f;
		}
		c = c.GetSuperClass();
	}
	sort(vProperty.begin(), vProperty.end(), SortProperty);;
	return vProperty;
}

bool utf8_check_is_valid(const std::string& string)
{
    int c,i,ix,n,j;
    for (i=0, ix=string.length(); i < ix; i++)
    {
        c = (unsigned char) string[i];
        //if (c==0x09 || c==0x0a || c==0x0d || (0x20 <= c && c <= 0x7e) ) n = 0; // is_printable_ascii
        if (0x00 <= c && c <= 0x7f) n=0; // 0bbbbbbb
        else if ((c & 0xE0) == 0xC0) n=1; // 110bbbbb
        else if ( c==0xed && i<(ix-1) && ((unsigned char)string[i+1] & 0xa0)==0xa0) return false; //U+d800 to U+dfff
        else if ((c & 0xF0) == 0xE0) n=2; // 1110bbbb
        else if ((c & 0xF8) == 0xF0) n=3; // 11110bbb
        //else if (($c & 0xFC) == 0xF8) n=4; // 111110bb //byte 5, unnecessary in 4 byte UTF-8
        //else if (($c & 0xFE) == 0xFC) n=5; // 1111110b //byte 6, unnecessary in 4 byte UTF-8
        else return false;
        for (j=0; j<n && i<ix; j++) { // n bytes matching 10bbbbbb follow ?
            if ((++i == ix) || (( (unsigned char)string[i] & 0xC0) != 0x80))
                return false;
        }
    }
    return true;
}
std::string GetInfo(ULONG_PTR ptr, UClassProxy c) {
	json j;

	json jInfo;
	DWORD iInfo = 0;

	DWORD structSize = 0;
	int iLoops = 0;
	auto vProperty = GetProps(c, structSize);
	//sort..
	//printf("struct size: %X\n", structSize);
	auto _AddItem = [&](std::string type, ULONG_PTR offset, std::string name, std::string  val, ULONG_PTR lParam = 0) {
		//printf("%04X Add: %s / %s / %s\n",offset, name.c_str(),type.c_str(),val.c_str());
		//validate uft-8
		if (!utf8_check_is_valid(val))
			val = "NON UTF-8";

		json i;
		i["type"] = type;
		i["offset"] = offset;
		i["name"] = name;
		i["val"] = val;
		i["lParam"] = lParam;
		jInfo[iInfo++] = i;
		i.dump();
	};

	std::function<void(std::string structName,UPropertyProxy fStruct, ULONG_PTR ptr, ULONG_PTR offset)> fnc = [&](std::string structName,UPropertyProxy fStruct, ULONG_PTR ptr, ULONG_PTR offset) {
		//iter child
		std::vector< UPropertyProxy> vProperty;

		UClassProxy c = fStruct.GetStruct().As<UClassProxy>();
		//list properties
		//TODO: CHECK SUPER
		UPropertyProxy f = c.GetChildren().As<UPropertyProxy>();

		if (f.ptr == 0)
			return;
		while (1) {
			if (!f.IsFunction()) {
				vProperty.push_back(f);
			}
			if (!f.HasNext()) {
				break;
			}
			f = f.GetNext();
			//break;
		}
		sort(vProperty.begin(), vProperty.end(), SortProperty);
		//add size to offset
		for(DWORD i = 0; i < vProperty.size();i++) {
			auto f = vProperty[i];
			if (i == 0) {

				if (f.GetOffset() > 0) {
					_AddItem("UNK", offset,structName+".MISSED", GetHex(f.GetOffset()));
					//print missed
				}
			}
			static int bIn = 0;
			if (f.IsStruct() ) {
				bIn++;
				fnc(structName+"."+f.GetName(),f, ptr, offset + f.GetOffset());
				bIn--;
			}
			else {
				DWORD arrayDim = f.GetArrayDim();
				if (arrayDim > 1) {
						DWORD size = f.GetSize();
						DWORD nSize = i + 1 < vProperty.size() ? (vProperty[i + 1].GetOffset() - f.GetOffset()) / arrayDim : arrayDim * size;
						for (DWORD j = 0; j < arrayDim; j++) {
							char name[512];
							
							UPropertyProxy cp = f.ptr + 0x80;// Read<DWORD64>(f.ptr + 0x90); //using this trick because we read class from *(+0x10)
							sprintf_s(name, 512, "%s.%s[%i]",structName.c_str(), f.GetName().c_str(), j);
							//sprintf_s(name, 512, "%p %s[%i]", f.ptr, cp.GetName().c_str(), j);

							ULONG_PTR lParam = 0;
							std::string value = GetObjectValue(ptr, &cp, offset + f.GetOffset(), lParam, true);//"value";

							cp = Read<DWORD64>(f.ptr + 0x90);
							_AddItem(cp.GetName(), offset + f.GetOffset()+ (j*nSize), name, value);
							//dwOffset += nSize;
						}
						continue;
					//_AddItem(f.GetClass().GetName(), offset+f.GetOffset(), structName+"."+f.GetName(), "ARRAY DIM"+std::to_string(f.GetArrayDim()));
					//continue;
				}
				//OutputDebugStringA(f.GetName().c_str());
				//auto pScriptStruct = ((UStructProperty *)pProperty)->Struct;
				ULONG_PTR lParam = 0;
				std::string value = GetObjectValue(ptr, &f, offset + f.GetOffset(), lParam, true);//"value";
				std::string name = structName;
				_AddItem(f.GetClass().GetName(), offset + f.GetOffset(), name.append(".").append(f.GetName()), value, lParam);
			}
		}
	};
	auto parseFnc = [fnc, _AddItem](std::vector< UPropertyProxy> vProperty, ULONG_PTR ptr, int structSize) {
		int offset = sizeof(UObject);
		for (int i = 0; i < vProperty.size(); i++) {
			auto f = vProperty[i];

			//check offset
			DWORD dwOffset = f.GetOffset();
			int size = dwOffset - offset;
			if (dwOffset > offset) {
				//printf("missed %X / %i\n", offset, size);
				_AddItem("UNK", offset, "MISSED", GetHex(size));
				offset += size;
				//print missed
				
			}

			size = f.GetSize();
			//printf("not missed %X / %i / %s\n", offset, size, f.GetName().c_str());
			if (f.IsStruct()) {
				fnc(f.GetName(),f, ptr, f.GetOffset());
			}
			else {
				auto arrayDim = f.GetArrayDim();
				if (arrayDim > 1) {
					DWORD nSize = i + 1 < vProperty.size() ? (vProperty[i + 1].GetOffset() - f.GetOffset()) / arrayDim : arrayDim * size;
					arrayDim = 1;
					for (DWORD j = 0; j < arrayDim; j++) {
						char name[124];

						sprintf_s(name, 124, "%s[%i]", f.GetName().c_str(), j);
						_AddItem("ARRAY", dwOffset, name, "ARRAY DIM");
						dwOffset += nSize;
					}
					continue;
				}
				ULONG_PTR lParam = 0;
				std::string value = GetObjectValue(ptr, &f, f.GetOffset(), lParam);
				std::string name = /*std::to_string(size) + */f.GetName();
				_AddItem(f.GetClass().GetName(), offset, name, value, lParam);
			}
			if (f.IsBool()) {
				//check if next val has diff offset
				if (i + 1 < vProperty.size() && dwOffset != vProperty[i + 1].GetOffset()) {
					offset += 1;
				}
			}
			else {
				offset += size;
			}
		}
		if (offset < structSize) {
			int size = structSize - offset;
			_AddItem("UNK", offset, "MISSED", GetHex(size));
		}
	};
	parseFnc(vProperty, ptr, structSize);

	j["name"] = ptr? UObjectProxy(ptr).GetName() : "CLASS";
	j["ptr"] = ptr;
	j["info"] = jInfo;

	json _j;
	_j["type"] = "info";
	_j["data"] = j;

	std::string ret;
	try
	{
		ret = _j.dump();
	}
	catch (json::exception& e) {
		printf("%i GOT EXCEPTION! %s\n",e.id,e.what());
	}
	//OutputDebugStringA(ret.c_str());
	return ret;

}
std::string GetInfo(ULONG_PTR ptr) {
	return GetInfo(ptr,UObjectProxy(ptr).GetClass().As<UClassProxy>());
}

std::string GetClass(ULONG_PTR ptr) {
	return GetInfo(NULL, UObjectProxy(ptr).As<UClassProxy>());
}


bool FindProp(ULONG_PTR pObj, std::string pText, UPropertyProxy& out) {
	DWORD structSize = 0;
	auto vProperty = GetProps(UObjectProxy(pObj).GetClass().As<UClassProxy>(), structSize);

	for (DWORD i = 0; i < vProperty.size(); i++) {
		auto p = vProperty[i];
		std::string name = p.GetName();
		bool bMatch = name == pText;
		auto dwOffset = p.GetOffset();
		if (!bMatch && p.IsStruct()) {
			UClassProxy c = p.GetStruct().As<UClassProxy>();
			//list properties
			//TODO: CHECK SUPER
			UPropertyProxy _f = c.GetChildren().As<UPropertyProxy>();

			while (!bMatch) {
				if (!_f.IsFunction()) {
					//check _f name
					name = p.GetName().append(".").append(_f.GetName());
					bMatch = name == pText;
					if (bMatch) {
						p = _f;
						break;
					}
				}
				if (!_f.HasNext()) {
					break;
				}
				_f = _f.GetNext();
				//break;
			}
		}
		if (bMatch) {
			out = p;
			return true;
		}
	}

	return false;
}

class FieldCache {
public:
	enum ETypes {
		T_UNK,
		T_BOOL,
		T_BYTE,
		T_INT,
		T_FLOAT,
		T_STRING
	};
	char szField[64];
	DWORD nOffset = 0;
	DWORD nType;
	FieldCache() {

	}
	FieldCache(const char* _szField) {
		strcpy_s(szField, _szField);
	}
	ULONG_PTR UGet(ULONG_PTR pObj) {
		DWORD off = Find(pObj);
		return off ? Read<ULONG_PTR>(pObj + off) : 0;
	}
	DWORD Find(ULONG_PTR pObj) {
		if (nOffset) return nOffset;

		UPropertyProxy p;
		if (FindProp(pObj, szField, p)) {
			DWORD dwOffset = p.GetOffset();
				nOffset = dwOffset;
				if (p.IsBool()) {
					nType = T_BOOL;
				}
				else if (p.IsByte()) {
					nType = T_BYTE;
				}
				else if (p.IsInt()) {
					nType = T_INT;
				}
				else if (p.IsFloat()) {
					nType = T_FLOAT;
				}
		}
		return nOffset;
	}
	sol::object Get(ULONG_PTR ptr) {
		if (nOffset || Find(ptr)) {
			if (nType & T_BOOL) {
				return sol::make_object(lua, Read<BYTE>((LPBYTE)ptr + nOffset));
			}
			else if (nType & T_BYTE) {
				return sol::make_object(lua, Read<BYTE>((LPBYTE)ptr + nOffset));
			}
			else if (nType & T_INT) {
				return sol::make_object(lua, Read<DWORD>((LPBYTE)ptr + nOffset));
			}
			else if (nType & T_FLOAT) {
				return sol::make_object(lua, Read<float>((LPBYTE)ptr + nOffset));
			}
		}
		return sol::make_object(lua, sol::lua_nil);
	}
};


DWORD64 FindObject(LPCSTR name, DWORD dwFlag = 0) {
	DWORD64 pArray = Read(gObj);
	for (DWORD i = 0; i < 9; i++) {
		DWORD64 pObjArr = Read(pArray + (8 * i));
		//printf("read %p\n", pObjArr);
		if (!pObjArr) break;
		FUObjectItem* fuObject = (FUObjectItem*)pObjArr;
		for (auto i = 0; i < 0x10000; ++i, ++fuObject) {
			UObjectProxy object = Read<FUObjectItem>(fuObject).Object;
			if (!object.ptr || (dwFlag && dwFlag != object.obj.ObjectFlags)) {
				continue;
			}
			auto objName = CNames::GetName(object.GetId());
			if (!strcmp(objName, name)) {
				//OutputDebugStringW(objName);
				return object.ptr;
			}
		}
	}

	return 0;
}

class AActor {
public:
	ULONG_PTR _this;
	AActor(ULONG_PTR ptr) : _this(ptr) {
	}
	int GetId() {
		if (getIdFnc) return getIdFnc(_this);
		return Read<int>((LPBYTE)_this + UObj_Offsets::dwNameIdOffset);
	}
	const char* GetName() {
		return CNames::GetName(GetId());
	}
};
class CWorld : public AActor {
public:
	CWorld(ULONG_PTR ptr) : AActor(ptr) {
	}
	std::vector<AActor> GetActors();
};
std::vector<AActor> CWorld::GetActors() {
	std::vector<AActor> v;


	static FieldCache fLevels = FieldCache("Levels");

	//now add x scanner..
	//loop all levels...
	if (!fLevels.Find(_this)) return v;
	TArray<ULONG_PTR> lBuf = Read<TArray<ULONG_PTR>>((LPBYTE)_this + fLevels.Find(_this)); //levels..

	ULONG_PTR* lvls = new ULONG_PTR[lBuf.Count];
	ReadTo(lBuf.Data, lvls, lBuf.Count * 8);
	for (int i = 0; i < lBuf.Count; i++) {
		ULONG_PTR level = lvls[i];

		ULONG_PTR pArr = level + UObj_Offsets::dwActorsList;
		if (getActorsFnc) pArr = getActorsFnc(level);
		if (pArr) {
			TArray<ULONG_PTR> buf = Read<TArray<ULONG_PTR>>(pArr);
			ULONG_PTR* ptrs = new ULONG_PTR[buf.Count];
			ReadTo(buf.Data, ptrs, buf.Count * 8);
			for (int i = 0; i < buf.Count; i++) {
				ULONG_PTR ptr = ptrs[i];
				if (ptr)
					v.push_back(AActor(ptr));
			}
			delete[] ptrs;
		}
	}
	delete[] lvls;
	//get level and list actors
	return v;
};
std::string GetList() {
	json j;
	if (hProcess) {
		auto e = AActor(Read<ULONG_PTR>(GetBase() + ENGINE_OFFSET)); ;// AActor((ULONG_PTR)GEngine);
		char msg[124];
		sprintf_s(msg, 124, "%p / eid: %i\n",e._this, e.GetId());
		OutputDebugStringA(msg);
		OutputDebugStringA(e.GetName());
		OutputDebugStringA(" --- READ ENGINE NAME!!!\n");
		//auto n = UObjectProxy(e._this).GetClass().GetName();
		//printf("name: %s\n", n.c_str());
		//return "";//
		std::vector<AActor> actors;
#ifdef UE3
		static FieldCache fGamePlayers = FieldCache("GamePlayers");
		DWORD dwOff = fGamePlayers.Find(e._this);
		auto pLocal = Read< DWORD64>(Read((DWORD64)e._this + dwOff));
		actors.insert(actors.begin(), AActor(pLocal));

		static FieldCache fActor = FieldCache("Actor");
		auto pActor = fActor.UGet(pLocal);
		actors.insert(actors.begin(), AActor(pActor));

		static FieldCache fPawn = FieldCache("Pawn");
		auto pPawn = fPawn.UGet(pActor);
		actors.insert(actors.begin(), AActor(pPawn));
#else
		static FieldCache fGameViewport = FieldCache("GameViewport");
		static FieldCache fWorld = FieldCache("World");

		//now add x scanner..
		ULONG_PTR ptr1 = fGameViewport.UGet(e._this);
		ULONG_PTR pWorld = 0;
		if (ptr1) {
			if (!fWorld.Find(ptr1)) {
				OutputDebugStringA("Could not find World property.. bruteforce..\n");
				for (UINT i = 0x30; i < 0x700; i += 8) {
					//get x name
					UObjectProxy pOff = Read<ULONG_PTR>((LPBYTE)ptr1 + i);
					if (!IsBadReadPtrEx((LPVOID)pOff.ptr)) {
						//..
						auto n = pOff.GetClass().GetName();
						if (n == "World") {
							pWorld = pOff.ptr;
							OutputDebugStringA("Found by bruteforce..\n");
							//sprintf_s(szMsg, 1024, "\n %04X WORLD %04X - %s\n", 0, i, n.c_str());
							//OutputDebugStringA(szMsg);
							break;
						}

					}
					//
				}
			}
			else {
				pWorld = fWorld.UGet(ptr1);
			}
		}
		if (pWorld) {
			CWorld w = CWorld(pWorld);
			actors = w.GetActors();
			actors.insert(actors.begin(), AActor(w._this));
		}
#endif
		actors.insert(actors.begin(), AActor(e._this));
		DWORD i = 0;
		for(DWORD g = 0; g < actors.size();g++) {
			auto a = actors[g];
			const char* name = a.GetName();

			json e;
			e["addr"] = a._this;
			e["name"] = name;
			e["class"] = UObjectProxy(a._this).GetClass().GetName();
			j[i++] = e;
		}

	}
	else {
		printf("no process?\n");
	}
	json _j;
	_j["type"] = "list";
	_j["data"] = j;
	std::string jsDump = _j.dump();

	return jsDump;
}
#pragma endregion UE4Parser


#pragma region Lua
bool LuaInit() {
	//x = 0;
	state.reset(new sol::state);
	lua.open_libraries();
	lua.new_usertype<FieldCache>("field_cache",
		sol::constructors<FieldCache(), FieldCache(const char*)>(),
		"get", &FieldCache::Get
		);
	lua.set_function("ToggleBit", [](WORD nBits, ULONG_PTR dwAddr) {
		return Write<BYTE>((LPVOID)dwAddr, SetBitState(dwAddr, nBits, !GetBitState(dwAddr, nBits)));
		});
	lua.set_function("WriteBit", [](WORD nBits, ULONG_PTR dwAddr, bool bVal) {
		return Write<BYTE>((LPVOID)dwAddr, SetBitState(dwAddr, nBits, bVal));
		});
	lua.set_function("WriteByte", [](ULONG_PTR dwAddr, BYTE bVal) {
		return Write<BYTE>((LPVOID)dwAddr, bVal);
		});
	lua.set_function(("WriteInt"), [](ULONG_PTR dwAddr, DWORD dwVal) {
		return Write<DWORD>((LPVOID)dwAddr, dwVal);
		});
	lua.set_function(("WriteFloat"), [](ULONG_PTR dwAddr, float fVal) {
		return Write<float>((LPVOID)dwAddr, fVal);
		});
	lua.set_function(("ReadF"), [](ULONG_PTR dwAddr) {
		return Read<float>((LPVOID)dwAddr);
		});
	lua.set_function("FindObject", [](LPCSTR objName) {
		return FindObject(objName);
		});
	lua.set_function(("GetEngine"), []() {
		auto e = AActor(Read<ULONG_PTR>(GetBase() + ENGINE_OFFSET));
		return (ULONG_PTR)e._this;
		});
	lua.set_function(("GetLocal"), []() {
		ULONG_PTR pRet = NULL;
		auto e = AActor(Read<ULONG_PTR>(GetBase() + ENGINE_OFFSET)); 

		static FieldCache fGameViewport = FieldCache("GameViewport");
		static FieldCache fWorld = FieldCache("World");

		//now add x scanner..
		ULONG_PTR ptr1 = fGameViewport.UGet(e._this);
		if (ptr1) {
			ptr1 = fWorld.UGet(ptr1);
			//
			static FieldCache fOwningGameInstance = FieldCache("OwningGameInstance");
			static FieldCache fLocalPlayers = FieldCache("LocalPlayers");
			static FieldCache fPlayerController = FieldCache("PlayerController");
			static FieldCache fAcknowledgedPawn = FieldCache("AcknowledgedPawn");

			char msg[124];
			auto ogi = Read<ULONG_PTR>((LPBYTE)ptr1 + fOwningGameInstance.Find(ptr1)); //owning game instance //read 190
			if (!ogi) return pRet;
			auto lp = Read<ULONG_PTR>(Read<ULONG_PTR>(ogi + fLocalPlayers.Find(ogi)));
			if (!lp) return pRet;
			auto pc = Read<ULONG_PTR>(lp + fPlayerController.Find(lp));
			if (!pc) return pRet;
			pRet = Read<ULONG_PTR>(pc + fAcknowledgedPawn.Find(pc));
		}
		return pRet;


		});
	lua.set_function(("GetOffset"), [](ULONG_PTR pObj, std::string pText) {
		UPropertyProxy p;
		return FindProp(pObj,pText,p) ? p.GetOffset() : 0;
		 });
	lua.set_function(("GetField"), [](ULONG_PTR pObj, std::string pText) {
		UPropertyProxy p;
		if(FindProp(pObj, pText, p)) {
			DWORD dwOffset = p.GetOffset();
				if (p.IsObject()) {
					return sol::make_object(lua, Read<DWORD64>((LPBYTE)pObj + dwOffset));
				}
				if (p.IsBool()) {
					return sol::make_object(lua, Read<BYTE>((LPBYTE)pObj + dwOffset));
				}
				else if (p.IsByte()) {
					return sol::make_object(lua, Read<BYTE>((LPBYTE)pObj + dwOffset));
				}
				else if (p.IsInt()) {
					return sol::make_object(lua, Read<DWORD>((LPBYTE)pObj + dwOffset));
				}
				else if (p.IsFloat()) {
					return sol::make_object(lua, Read<float>((LPBYTE)pObj + dwOffset));
				}
				else if (p.IsArray()) {
					std::vector<ULONG_PTR> ret;

					TArray<ULONG_PTR> buf = Read<TArray<ULONG_PTR>>((LPBYTE)pObj + dwOffset);
					ULONG_PTR* ptrs = new ULONG_PTR[buf.Count];
					ReadTo(buf.Data, ptrs, buf.Count * 8);
					for (DWORD i = 0; i < buf.Count; i++) {
						ret.push_back(ptrs[i]);
					}
					delete[] ptrs;
					return sol::make_object(lua, sol::as_table(ret));
				}
		}
		return sol::make_object(lua, sol::lua_nil);
		});
	lua.set_function(("SetField"), [](ULONG_PTR pObj, std::string pText, float fVal) {
		DWORD pRet = 0;
		UPropertyProxy p;
		if (FindProp(pObj, pText, p)) {
			DWORD dwOffset = p.GetOffset();
				pRet = 1;

				if (p.IsBool()) {
					//edit bit state
					//BYTE b = Read<BYTE>((LPBYTE)lastScan + dwOffset);
					BYTE newB = fVal;// ToggleBitState(lastScan + dwOffset, p.GetBitMask(), bToggle ? !CheckBitState(lastScan + dwOffset, p.GetBitMask()) : Button_GetCheck(hEditCB));
					char msg[124];
					sprintf_s(msg, 124, "%04X B: %i\n", p.GetBitMask(), newB);
					OutputDebugStringA(msg);
					pRet = Write<BYTE>(pObj + dwOffset, SetBitState(pObj + dwOffset, p.GetBitMask(), newB));
				}
				else if (p.IsByte()) {
					pRet = Write<BYTE>((LPBYTE)pObj + dwOffset, fVal);
				}
				else if (p.IsInt()) {
					pRet = Write<DWORD>((LPBYTE)pObj + dwOffset, fVal);
				}
				else if (p.IsFloat()) {
					pRet = Write<float>((LPBYTE)pObj + dwOffset, fVal);
				}
				else if (p.IsObject()) {
					pRet = Write<DWORD64>((LPBYTE)pObj + dwOffset, fVal);
				}
		}
		return pRet;
		});
	lua.set_function(("Log"), [](std::string log) {
		OutputDebugStringA(log.c_str());
		});
	lua.set_function(("WSLog"), [](std::string log) {
		//send log..

		json _j;
		_j["type"] = "log";
		_j["log"] = log;
		std::string send_stream = _j.dump();
		for(DWORD i = 0; i < vConnects.size();i++) {
			auto connection = vConnects[i];
			connection->send(send_stream, [](const SimpleWeb::error_code& /*ec*/) { /*handle error*/ });
		}
		});
	return true;
}
#pragma endregion Lua


#pragma region WebSocket

int split_in_args(std::vector<std::string>& qargs, std::string command) {
	int len = command.length();
	bool qot = false, sqot = false;
	int arglen;
	for (int i = 0; i < len; i++) {
		int start = i;
		if (command[i] == '\"') {
			qot = true;
		}
		else if (command[i] == '\'') sqot = true;

		if (qot) {
			i++;
			start++;
			while (i < len && command[i] != '\"')
				i++;
			if (i < len)
				qot = false;
			arglen = i - start;
			i++;
		}
		else if (sqot) {
			i++;
			while (i < len && command[i] != '\'')
				i++;
			if (i < len)
				sqot = false;
			arglen = i - start;
			i++;
		}
		else {
			while (i < len && command[i] != ' ')
				i++;
			arglen = i - start;
		}
		qargs.push_back(command.substr(start, arglen));
	}
	return qargs.size();
}
void ParseMessage(std::shared_ptr<WsServer::Connection> connection, std::string msg) {
	static std::map<std::string, std::function<void(std::shared_ptr<WsServer::Connection> connection, std::string msg, int nArgs, std::vector<std::string> vArgs)>> vHandles;
	static bool bInit = false;
	if (!bInit) {

		vHandles[("do_script")] = [](std::shared_ptr<WsServer::Connection> connection, std::string msg, int nArgs, std::vector<std::string> vArgs) {
			auto script = msg.substr(10);//strlen("do_script "));
			OutputDebugStringA(script.c_str());
			try {
				sol::protected_function_result result = lua.do_string(script);
				if (!result.valid()) {
					sol::error e = result;
					throw e;
				}
			}
			catch (sol::error const& e) {
				//printf("Load Error %s\n", e.what());
				//OutputDebugStringA(e.what());

				json _j;
				_j["type"] = "log";
				_j["log"] = std::string("script error: ").append(e.what()).append("\n");
				std::string send_stream = _j.dump();//bRet ? "added to sonic list" : "failed to add to sonic list";

				connection->send(send_stream, [](const SimpleWeb::error_code& /*ec*/) { /*handle error*/ });
			}

		};
		vHandles["get_list"] = [](std::shared_ptr<WsServer::Connection> connection, std::string msg, int nArgs, std::vector<std::string> vArgs) {

			std::string send_stream = GetList().c_str();//bRet ? "added to sonic list" : "failed to add to sonic list";

			connection->send(send_stream, [](const SimpleWeb::error_code& /*ec*/) { /*handle error*/ });
		};
		vHandles["get_info"] = [](std::shared_ptr<WsServer::Connection> connection, std::string msg, int nArgs, std::vector<std::string> vArgs) {
			auto arg = vArgs[1]; //
			//OutputDebugStringA(arg.c_str());

			std::string send_stream = GetInfo(_atoi64(arg.c_str())).c_str();//bRet ? "added to sonic list" : "failed to add to sonic list";

			connection->send(send_stream, [](const SimpleWeb::error_code& /*ec*/) { /*handle error*/ });
		};
		vHandles["get_class"] = [](std::shared_ptr<WsServer::Connection> connection, std::string msg, int nArgs, std::vector<std::string> vArgs) {
			auto arg = vArgs[1]; //
			//OutputDebugStringA(arg.c_str());

			std::string send_stream = GetClass(_atoi64(arg.c_str())).c_str();//bRet ? "added to sonic list" : "failed to add to sonic list";

			connection->send(send_stream, [](const SimpleWeb::error_code& /*ec*/) { /*handle error*/ });
		};
		bInit = true;
	}
	std::vector<std::string> vArgs;
	int nArgs = split_in_args(vArgs, msg);
	auto cmd = vArgs[0];
	auto f = vHandles[cmd];
	if (f)
		f(connection, msg, nArgs, vArgs);
	else
		printf("unknown cmd: %i / %s\n", nArgs, cmd.c_str());
}
DWORD wsStart = 0;
std::thread StartWebServer() {
	wsStart = GetTickCount() + 10000;

	server.config.port = 1357;
	auto& echo = server.endpoint["^/echo/?$"];

	echo.on_message = [](std::shared_ptr<WsServer::Connection> connection, std::shared_ptr<WsServer::InMessage> message) {
		auto message_str = message->string();
		ParseMessage(connection, message_str);

	};

	echo.on_open = [](std::shared_ptr<WsServer::Connection> connection) {
		wsStart = 0;
		vConnects.push_back(connection);
	};

	// See RFC 6455 7.4.1. for status codes
	echo.on_close = [](std::shared_ptr<WsServer::Connection> connection, int status, const std::string& /*reason*/) {
		vConnects.erase(std::remove(vConnects.begin(), vConnects.end(), connection), vConnects.end());
	};

	// See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
	echo.on_error = [](std::shared_ptr<WsServer::Connection> connection, const SimpleWeb::error_code& ec) {
		//std::cout << "Server: Error in connection " << connection.get() << ". "
		//	<< "Error: " << ec << ", error message: " << ec.message() << std::endl;
	};

	printf("[*] Initialized Server.\n");
	std::thread server_thread([]() {
		// Start WS-server
		server.start();
		});


	return server_thread;
}
#pragma endregion WebSocket



template<class T> T __ROL__(T value, int count)
{
	const DWORD nbits = sizeof(T) * 8;

	if (count > 0)
	{
		count %= nbits;
		T high = value >> (nbits - count);
		if (T(-1) < 0) // signed value
			high &= ~((T(-1) << count));
		value <<= count;
		value |= high;
	}
	else
	{
		count = -count % nbits;
		T low = value << (nbits - count);
		value >>= count;
		value |= low;
	}
	return value;
}
#define _BYTE BYTE
#define _WORD WORD
#define _QWORD DWORD64
#define _DWORD DWORD
inline BYTE  __ROR1__(BYTE  value, int count) { return __ROL__((BYTE)value, -count); }
inline BYTE  __ROL1__(BYTE  value, int count) { return __ROL__((BYTE)value, count); }
inline WORD __ROL2__(WORD value, int count) { return __ROL__((WORD)value, count); }
inline WORD __ROR2__(WORD value, int count) { return __ROL__((WORD)value, -count); }
inline DWORD   __ROL4__(DWORD value, int count) { return __ROL__((DWORD)value, count); }
inline DWORD   __ROR4__(DWORD value, int count) { return __ROL__((DWORD)value, -count); }
inline DWORD64 __ROR8__(DWORD64 value, int count) { return __ROL__((DWORD64)value, -count); }
inline DWORD64 __ROL8__(DWORD64 value, int count) { return __ROL__((DWORD64)value, count); }
#define HIDWORD(x)  (*((DWORD*)&(x)+1))
#define LODWORD(x)   (*((DWORD*)&(x)))   // low word

#define HIDWORD(x)  (*((DWORD*)&(x)+1))
#define LODWORD(x)   (*((DWORD*)&(x)))   // low word
#define LOWORD(x)   (*((WORD*)&(x)))   // low word

#define BYTEn(x, n)   (*((BYTE*)&(x)+n))
#define WORDn(x, n)   (*((WORD*)&(x)+n))
#define WORD1(x)   WORDn(x,  1)
#define WORD2(x)   WORDn(x,  2)         // third word of the object, unsigned



#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD))
#define PEFHDROFFSET(a) (PIMAGE_FILE_HEADER)((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
#define SECHDROFFSET(ptr) (PIMAGE_SECTION_HEADER)((LPVOID)((BYTE *)(ptr)+((PIMAGE_DOS_HEADER)(ptr))->e_lfanew+SIZE_OF_NT_SIGNATURE+sizeof(IMAGE_FILE_HEADER)+sizeof(IMAGE_OPTIONAL_HEADER)))

PIMAGE_SECTION_HEADER getCodeSection(LPVOID lpHeader) {
	PIMAGE_FILE_HEADER pfh = PEFHDROFFSET(lpHeader);
	if (pfh->NumberOfSections < 1)
	{
		return NULL;
	}
	PIMAGE_SECTION_HEADER psh = SECHDROFFSET(lpHeader);
	return psh;
}
size_t replace_all(std::string& str, const std::string& from, const std::string& to) {
	size_t count = 0;

	size_t pos = 0;
	while ((pos = str.find(from, pos)) != std::string::npos) {
		str.replace(pos, from.length(), to);
		pos += to.length();
		++count;
	}

	return count;
}

bool is_hex_char(const char& c) {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F');
}
std::vector<int> pattern(std::string patternstring) {
	std::vector<int> result;
	const uint8_t hashmap[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
		0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
		0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
	};
	replace_all(patternstring, "??", " ? ");
	replace_all(patternstring, "?", " ?? ");
	replace_all(patternstring, " ", "");
	//boost::trim(patternstring);
	//assert(patternstring.size() % 2 == 0);
	for (std::size_t i = 0; i < patternstring.size() - 1; i += 2) {
		if (patternstring[i] == '?' && patternstring[i + 1] == '?') {
			result.push_back(0xFFFF);
			continue;
		}
		//assert(is_hex_char(patternstring[i]) && is_hex_char(patternstring[i + 1]));
		result.push_back((uint8_t)(hashmap[patternstring[i]] << 4) | hashmap[patternstring[i + 1]]);
	}
	return result;
}

std::vector<std::size_t> find_pattern(const uint8_t* data, std::size_t data_size, const std::vector<int>& pattern) {
	// simple pattern searching, nothing fancy. boyer moore horsepool or similar can be applied here to improve performance
	std::vector<std::size_t> result;
	for (std::size_t i = 0; i < data_size - pattern.size() + 1; i++) {
		std::size_t j;
		for (j = 0; j < pattern.size(); j++) {
			if (pattern[j] == 0xFFFF) {
				continue;
			}
			if (pattern[j] != data[i + j]) {
				break;
			}
		}
		if (j == pattern.size()) {
			result.push_back(i);
		}
	}
	return result;
}
std::vector<std::size_t> AOBScan(std::string str_pattern) {
	std::vector<std::size_t> ret;
	HANDLE hProc = hProcess;

	ULONG_PTR dwStart = GetBase();

	LPVOID lpHeader = malloc(0x1000);
	ReadProcessMemoryCallback(hProc, (LPCVOID)dwStart, lpHeader, 0x1000, NULL);

	DWORD delta = 0x1000;
	LPCVOID lpStart = 0; //0
	DWORD nSize = 0;// 0x548a000;

	PIMAGE_SECTION_HEADER SHcode = getCodeSection(lpHeader);
	if (SHcode) {
		nSize = SHcode->Misc.VirtualSize;
		delta = SHcode->VirtualAddress;
		lpStart = ((LPBYTE)dwStart + delta);
	}
	if (nSize) {
		LPVOID lpCodeSection = malloc(nSize);
		ReadProcessMemoryCallback(hProc, lpStart, lpCodeSection, nSize, NULL);

		//sprintf_s(szPrint, 124, "Size: %i / Start:%p / Base: %p", nSize, dwStart,lpStart);
		//MessageBoxA(0, szPrint, szPrint, 0);
		//
		auto res = find_pattern((const uint8_t*)lpCodeSection, nSize, pattern(str_pattern.c_str()));
		ret = res;
		for (UINT i = 0; i < ret.size(); i++) {
			ret[i] += delta;
		}

		free(lpCodeSection);
	}
	else {
		printf("bad .code section.\n");
	}
	free(lpHeader);


	return ret;
}




DWORD DoScan(std::string pattern, DWORD offset = 0, DWORD base_offset = 0, DWORD pre_base_offset = 0, DWORD rIndex = 0) {
	//ULONG_PTR dwBase = (DWORD_PTR)GetModuleHandleW(NULL);
	auto r = AOBScan(pattern);
	if (!r.size())
		return 0;
	//char msg[124];
	//sprintf_s(msg,124,"%s ret %i\n",pattern.c_str(),r.size() );
	//OutputDebugStringA(msg);
	DWORD ret = r[rIndex] + pre_base_offset;
	if (offset == 0) {
		return ret + base_offset;
	}
	ret = ret + Read<DWORD>((LPBYTE)GetBase() + ret + offset) + base_offset;
	//ret = ret + *(DWORD*)(dwBase + ret + offset) + base_offset;
	return ret;
}

void VerifyOffsets() {
	//first lets verify SuperClass
	UObjectProxy p(Read(GetBase() + ENGINE_OFFSET));
	auto c = p.GetClass().As<UClassProxy>();
	auto pEngSuperName = c.GetSuperClass().GetName();
	printf("[*] SuperClass: %s\n", pEngSuperName.c_str());
	//find C_SemiSolidWire
	auto pProp = c.GetSuperClass().GetSuperClass().GetChildren().As<UPropertyProxy>().GetNext();
	while (pProp.ptr && pProp.GetName() != "C_SemiSolidWire") {
		pProp = pProp.GetNext();
	}

	if (pProp.GetOffset() <= 0x30) {
		printf("bad offset?\n");
		UObj_Offsets::dwOffOffset += 4;
	}
	printf("Got Offset! %04X\n", UObj_Offsets::dwOffOffset);
	auto pInner = pProp.GetInner();
	while (pInner.GetName() != "Color") {
		printf("bad inner?\n");
		UObj_Offsets::dwInnerOffset += 8;
		pInner = pProp.GetInner();
	}
	printf("Got inner! %04X\n", UObj_Offsets::dwInnerOffset);
	//verify inner
}

void InitLastOasis() {
	UObj_Offsets::dwPropSize = 0x50;
	UObj_Offsets::dwSizeOffset = 0x30;//?
	UObj_Offsets::dwOffOffset = 0x44;
	UObj_Offsets::dwActorsList = 0x98;//
	UObj_Offsets::dwChildOffset = 0x68;//
	UObj_Offsets::dwSuperClassOffset2 = 0x40;
	sWndFind = L"Last Oasis  ";
	ENGINE_OFFSET = 0x3dc2c18; //48 8B 0D ?? ?? ?? ?? 41 B8 01 00 00 00 0F 28 F3

	DWORD FNAME_POOL = 0x3cac580;// DoScan("74 09 48 8D 15 ?? ?? ?? ?? EB 16", 3, 7, 2);// 0x3CAB400; //74 09 48 8D 15 ?? ?? ?? ?? EB 16

	fNamePool = GetBase()+FNAME_POOL;
	printf("pEng: %p\n", Read(GetBase()+ENGINE_OFFSET));
}
void InitBorderlands3() {
	sWndFind = L"Borderlands® 3  ";
	ENGINE_OFFSET = 0x6A09A08; //48 8B 88 ?? ?? 00 00 48 85 C9 74 3F, -7
}

void InitDeadSide() {
	sWndFind = L"Deadside  ";
	ENGINE_OFFSET = 0x36F7C70;
	fNamePool = GetBase() + 0x35F9940;
	//printf("namepool: %p\n",fNamePool);
	UObj_Offsets::dwActorsList = 0x98;//
	UObj_Offsets::dwPropSize = 0x50;
	UObj_Offsets::dwChildOffset = 0x48;//
	UObj_Offsets::dwSuperClassOffset2 = 0x40;//
}


/* MOVED TO GAME.HPP

void InitPubGSteam2() {
	hProcess = NULL;
	base = 0;
	sWndFind = L"PLAYERUNKNOWN'S BATTLEGROUNDS ";
	NAME_CHUNK = 0x3FC0;
	dwOffOffset = 0x58;
	ENGINE_OFFSET = 0x738D8A0;
		//set x
		UObj_Offsets::dwSuperClassOffset2 = 0x0C0;
	UObj_Offsets::dwSizeOffset = 0x38;//?
	UObj_Offsets::dwStructOffset = 0x50;//?

	UObj_Offsets::dwInnerOffset = 0x80;//?
	DWORD dwPropSize = 0x60;//?
	UObj_Offsets::dwChildOffset = 0x50;//?
	UObj_Offsets::dwNextOffset = 0x30;//?


#define NAME_OFF 0x0008
#define NAME_XOR 0x5A66C079
#define NAME_XOR2 0xD53CD882
#define NAME_BROR 0x0000
#define NAME_KEY 0x000C
#define CLASS_OFF 0x010
#define ClassXor1 0x38820DBDDF70FCFE
#define ClassXor2 0xD25F1A4D72264028
#define ClassShift 0
#define ClassXorKey 0x0000000000000002

	getIdFnc = [](ULONG_PTR _this) {
		//18-05
		DWORD dw1 = Read<DWORD>((LPBYTE)_this + NAME_OFF);
		DWORD r1 = (NAME_BROR ? __ROR4__ : __ROL4__)(dw1 ^ NAME_XOR, NAME_KEY);
		DWORD v1 = r1;
		r1 = v1 ^ ((r1 << 0x10) ^ NAME_XOR2);
		return r1;
	};
	getClassFnc = [](ULONG_PTR _this) {
		DWORD64 pVal = Read<DWORD64>((LPBYTE)_this + CLASS_OFF);
		ULONG_PTR UObjectVariable_ROL8 = (ClassXorKey) ? (ClassShift ? __ROR8__ : __ROL8__)(pVal ^ ClassXor1, ClassXorKey) : pVal ^ ClassXor1;
		auto ret = (UObjectVariable_ROL8 ^ (UObjectVariable_ROL8 << 32) ^ ClassXor2);
		return ret;
	};

	getEncObjFnc = [](ULONG_PTR v4) { //RootComponent..
		return 0;//TODO
	};
	getOuterClassFnc = [](ULONG_PTR _this) {
		return 0;//TODO
	};
	getActorsFnc = [](ULONG_PTR _this) {
		return 0;//TODO
	};
	GetBase();
	GScan();
}
*/
INT64 ActorDec(INT64 v15) //48 63 40 08 41 8B F1 4C 8D 3C C5 00 00 00 00 49 8D 04 3F 49 C1 EF 03 
{
	unsigned __int64 v16; // r9
	__int64 v21; // [rsp+40h] [rbp+18h]
	v16 = v15 >> 32;
	LODWORD(v15) = ((unsigned __int16)v15 ^ ((unsigned int)v15 >> 16) | v15 & 0xFFFF0000) - 1629592062;
	LODWORD(v21) = ((unsigned __int16)v15 ^ ((unsigned int)v15 >> 16) | ((unsigned __int16)__ROR2__(WORD1(v15), 8) << 16)) ^ 0x9EDE6602;
	LODWORD(v15) = ((unsigned __int16)__ROR2__(v16 ^ WORD1(v16), 8) | ((unsigned __int16)__ROR2__(WORD1(v16), 8) << 16))
		- 1648255678;
	HIDWORD(v21) = (v15 & 0xFFFF0000 | (unsigned __int16)__ROR2__(v15 ^ WORD1(v15), 8)) ^ 0x623E62BE;
	return v21;
}

void InitPubGLite() {
	sWndFind = L"PUBG LITE ";
	ENGINE_OFFSET = 0x4517870;
	NAME_CHUNK = 0x408C;
	UObj_Offsets::dwChildOffset = 0x88;//?
	UObj_Offsets::dwOffOffset = 0x44;
	UObj_Offsets::dwSizeOffset = 0x30;
	UObj_Offsets::dwInnerOffset = 0x70;
	UObj_Offsets::dwStructOffset = 0x128;
	UObj_Offsets::dwPropSize = 0x70;//
	UObj_Offsets::dwSuperClassOffset2 = 0x80;
	getIdFnc = [](ULONG_PTR _this) {
		auto ID = Read<DWORD>((LPBYTE)_this + 0x0C);
		auto dId = __ROL4__(ID ^ 0x0F7B20EA6, 0x0E);
		return  dId ^ (dId << 16) ^ 0x0F914F7B2;
	};

	getClassFnc = [](ULONG_PTR _this) {
		DWORD64 pVal = Read<DWORD64>((LPBYTE)_this + 0x18);
		ULONG_PTR v6 = __ROR8__(pVal ^ 0x470898FB6D10C7AC, 0x1C);
		return (v6 ^ (v6 << 32) ^ 0x5DE5A22A6289A4F);
	};
	getOuterClassFnc = [](ULONG_PTR _this) {
		DWORD64 pVal = Read<DWORD64>((LPBYTE)_this + UObj_Offsets::dwSuperClassOffset2);
		ULONG_PTR v6 = __ROL8__(pVal ^ 0x94426FF1A564B5E8, 0x13);
		return (v6 ^ (v6 << 32) ^ 0x72BCED0738B42294);
	};

	getActorsFnc = [](ULONG_PTR level) {
		return ActorDec(Read<ULONG_PTR>(level + 0x260));;//TODO
	};
}



#include "Game.hpp"

HANDLE GetFirstThread()
{
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnap || hSnap == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(te);
	Thread32First(hSnap, &te);
	auto pid = (DWORD)hProcess;// GetCurrentProcessId();
	LARGE_INTEGER lowest_creation = {};
	lowest_creation.QuadPart = MAXLONGLONG;
	int lowest_tid = 0;
	do
	{
		if (te.th32OwnerProcessID == pid)
		{
			FILETIME c = { 0 }, e = { 0 }, k = { 0 }, u = { 0 };

			auto hThread = OpenThread(THREAD_ALL_ACCESS, 0, te.th32ThreadID);
			if (!hThread || hThread == INVALID_HANDLE_VALUE)
				continue;

			GetThreadTimes(hThread, &c, &e, &k, &u);
			LARGE_INTEGER cInt = { 0 };
			cInt.HighPart = c.dwHighDateTime;
			cInt.LowPart = c.dwLowDateTime;

			if (cInt.QuadPart < lowest_creation.QuadPart)
			{
				lowest_creation.QuadPart = cInt.QuadPart;
				lowest_tid = te.th32ThreadID;
			}

			CloseHandle(hThread);
		}
	} while (Thread32Next(hSnap, &te));

	CloseHandle(hSnap);
	return OpenThread(THREAD_ALL_ACCESS, 0, lowest_tid);
}
ULONG_PTR FindTls() {
	static ULONG_PTR pTls = 0;
	if (!pTls) {
		//..find 
		typedef LONG(__stdcall* t_NtQueryInformationThread)(HANDLE ThreadHandle, int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
		t_NtQueryInformationThread NtQueryInformationThread = (decltype(NtQueryInformationThread))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

		typedef struct _CLIENT_ID {
			HANDLE UniqueProcess;
			HANDLE UniqueThread;
		} CLIENT_ID, * PCLIENT_ID;

		typedef struct _THREAD_BASIC_INFORMATION {
			LONG ExitStatus;
			PVOID TebBaseAddress;
			CLIENT_ID ClientId;
			ULONG_PTR AffinityMask;
			LONG Priority;
			LONG BasePriority;
		} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

		// get main thread TEB and read +0x58
		THREAD_BASIC_INFORMATION tbi = { 0 };
		auto hThread = GetFirstThread();
		ULONG outlen = 0;
		auto ret = NtQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), &outlen);

		char msg[124];
		sprintf_s(msg, 124, "%p / %x / ptls: %p / %p\n", hThread, ret,tbi.TebBaseAddress, sizeof(tbi));
		OutputDebugStringA(msg);
		if (ret) {
			//OutputDebugStringA("Bad query!\n");
			return 0;
		}
		//OutputDebugStringA("Got query!\n");

		pTls = Read<uintptr_t>((LPBYTE)tbi.TebBaseAddress + 0x58);

		//char msg[124];
		//sprintf_s(msg, 124, "ptls: %p / %p\n", tbi.TebBaseAddress, pTls);
		//OutputDebugStringA(msg);

	}
	return pTls;
}
void InitPaladins() {
	bool bRealmRoyale = sWndFind == L"Realm Royale (64-bit, DX11)";
	bool bSmite = sWndFind == L"Smite (64-bit, DX9)";
	bool bPaladins = sWndFind == L"Paladins (64-bit, DX11)";

	GetBase();

	//find engine and gnames
	ENGINE_OFFSET =  DoScan("48 8B 0D ?? ?? ?? ?? 48 8B 89 ?? ?? ?? ?? 48 8B 41 60", 3, 7);
	printf("ENGINE RESULT: %p\n", ENGINE_OFFSET);


	//ENGINE_OFFSET = 0x0362FD90;
	//UObj_Offsets::dwStructOffset = 0xB0;
	//UObj_Offsets::dwSuperClassOffset2 = 0x78;
	UObj_Offsets::dwNameIdOffset = 0x48;
	UObj_Offsets::dwChildOffset = 0x80;//
	UObj_Offsets::dwNextOffset = 0x60;//
	//UObj_Offsets::dwInnerOffset = 0x98;//
	UObj_Offsets::dwOffOffset = 0x7C;
	/*getClassFnc = [](ULONG_PTR _this) {
		return Read(_this + 0x50);
	};*/
	getOuterClassFnc = [](ULONG_PTR _this) {
		return Read(_this + 0x78);
	};
	UObj_Offsets::dwPropSize = 0x88;
	UObj_Offsets::dwSizeOffset = 0x68;
	UObj_Offsets::dwBitmaskOffset = 0x98;

	getNameFnc = [](DWORD id) { //Paladins
		//00007FF746F367B9 | 48:8D15 B05E1702                  | lea     rdx, qword ptr ds:[0x7FF7490AC670]                                             | 00007FF7490AC670:"d:\\build\\paladins\\3.2\\development\\src\\core\\inc\\AntiCheatArray.h"
		static char m_name[256];
		m_name[0] = 0;

		static ULONG_PTR cTls = FindTls();


		DWORD64 toRead = Read<DWORD64>(cTls + (Read<DWORD>(GetBase() + 0x413D2D4) * 8));
		DWORD toAdd = 8 * (id&0x1FF) + 0x30;

		auto xorKey = Read<ULONG_PTR>((LPBYTE)toRead + toAdd);
		auto enc = Read<DWORD64>(Read<DWORD64>(GetBase() + 0x363694C) + id * 8);
		auto pPtr = (LPBYTE)(enc ^ xorKey);

		ReadTo((LPVOID)&pPtr[0x14], m_name, sizeof(m_name) - 1);
		return m_name;
	};

	if (bRealmRoyale) getNameFnc = [](DWORD id) { //RR
		//00007FF746F367B9 | 48:8D15 B05E1702                  | lea     rdx, qword ptr ds:[0x7FF7490AC670]                                             | 00007FF7490AC670:"d:\\build\\paladins\\3.2\\development\\src\\core\\inc\\AntiCheatArray.h"
		static char m_name[256];
		m_name[0] = 0;

		static ULONG_PTR cTls = FindTls();


		DWORD64 toRead = Read<DWORD64>(cTls + (Read<DWORD>(GetBase() + 0x38277C4) * 8)); //rsi
		DWORD toAdd = 8 * (id&0x1ff ) + 0x30;

		auto xorKey = Read<ULONG_PTR>((LPBYTE)toRead + toAdd);
		auto enc = Read<DWORD64>(Read<DWORD64>(GetBase() + 0x2CEC03C) + id * 8); 
		auto pPtr = (LPBYTE)(enc ^ xorKey);
		
		//sprintf_s(m_name, 256, "%p GETNAMES: %i - %p / %p / %p / [%p ^ %p = %p]\n", Read<DWORD64>(GetBase() + 0x2CEC03C), id, toRead, toAdd, cTls, enc,xorKey,pPtr);
		//OutputDebugStringA(m_name);

		ReadTo((LPVOID)&pPtr[0x14], m_name, sizeof(m_name) - 1);
		return m_name;
	};

	//smite
	if(bSmite) getNameFnc = [](DWORD id) { //RR
		//00007FF746F367B9 | 48:8D15 B05E1702                  | lea     rdx, qword ptr ds:[0x7FF7490AC670]                                             | 00007FF7490AC670:"d:\\build\\paladins\\3.2\\development\\src\\core\\inc\\AntiCheatArray.h"
		static char m_name[256];
		m_name[0] = 0;

		static ULONG_PTR cTls = FindTls();


		DWORD64 toRead = Read<DWORD64>(cTls + (Read<DWORD>(GetBase() + 0x40CD024) * 8)); //rsi
		DWORD toAdd = 8 * (id & 0x7f) + 0x30;

		auto xorKey = Read<ULONG_PTR>((LPBYTE)toRead + toAdd);
		auto enc = Read<DWORD64>(Read<DWORD64>(GetBase() + 0x364CC7C) + id * 8);
		auto pPtr = (LPBYTE)(enc ^ xorKey);

		//sprintf_s(m_name, 256, "%p GETNAMES: %i - %p / %p / %p / [%p ^ %p = %p]\n", Read<DWORD64>(GetBase() + 0x2CEC03C), id, toRead, toAdd, cTls, enc,xorKey,pPtr);
		//OutputDebugStringA(m_name);

		ReadTo((LPVOID)&pPtr[0x14], m_name, sizeof(m_name) - 1);
		return m_name;
	};

	//getNameFnc(0x1A03B);

	extern void BruteStruct();
	BruteStruct();
}

void BruteStruct() {
	//brute plz

	auto e = UObjectProxy(Read<ULONG_PTR>(GetBase() + ENGINE_OFFSET));
	//verify class
	for (DWORD i = 0; i < 0x200; i += 8) {
		UObjectProxy ptr = Read<ULONG_PTR>(e.ptr + i);
		if (ptr.ptr && e.ptr != ptr.ptr && ptr.GetId() == e.GetId()) {
			UObj_Offsets::dwClassOffset = i;
			std::string pName = ptr.GetName();
			printf("CLASS %04X test %s\n", i, ptr.GetName().c_str());
			break;
		}

	}


	auto c = e.GetClass().As<UClassProxy>();
	auto cName = c.GetName();
	printf("Engine: %s / %s\n", e.GetName(),c.GetName().c_str());

	//todo, find id?
	//find offset
	//find child and next

	//verify super
	for (DWORD i = 0; i < 0x200; i+=8) {
		UObjectProxy ptr = Read<ULONG_PTR>(c.ptr + i);
		std::string pName = ptr.ptr ? ptr.GetName() : "";
		if (ptr.ptr && strstr(pName.c_str(), "GameEngine") && pName != cName) {
			printf("SUPER CLASS %04X test %s\n", i, ptr.GetName().c_str());
			UObj_Offsets::dwSuperClassOffset2 = i;
			break;
		}
	}

	UPropertyProxy f;
	//scan childs
	//find C_SemiSolidWire
	UClassProxy scanClass = c;
	auto fScan = scanClass.GetChildren().As< UPropertyProxy>();
	while (!f.ptr) {
		auto fName = fScan.GetName();
		if (fName == "None") {
			auto nextClass = scanClass.GetSuperClass();
			if (nextClass== scanClass) break; //no more classes..
			scanClass = nextClass;
			fScan = scanClass.GetChildren().As< UPropertyProxy>();
		}
		else {
			//printf("Child: %s\n", fScan.GetName().c_str());
			if (fName == "C_SemiSolidWire") {
				f = fScan;
			}
			fScan = fScan.GetNext();
		}
	}
	printf("Found: %p\n", f.ptr);
	if (f.ptr) {
		OutputDebugString("FOUND SOLID WIRE!\n");
		/*if (f.GetOffset() <= 0x30) {
			UObj_Offsets::dwOffsetffset += 8;
		}*/
		auto pInner = f.GetInner();
		while (pInner.GetName() != "Color") {
			UObj_Offsets::dwInnerOffset += 8;
			pInner = f.GetInner();
		}
		char msg[124];
		sprintf_s(msg, 124, "%04X INNER SEARCH! %s / %p / %p \n", UObj_Offsets::dwInnerOffset, pInner.GetName().c_str(), f.ptr, pInner.ptr);
		OutputDebugStringA(msg);
		for (int i = 0x180; i >= 0x28; i -= 8) {
			UObjectProxy ptr = Read<ULONG_PTR>(pInner.ptr + i);
			if (ptr.ptr && ptr.ptr > 0x10000000000 && ptr.GetId() && ptr.GetId() < 0x100000) {
				UObjectProxy p = ptr;
				auto n = p.GetName();
				if (!n.empty() && (n == "A" || n == "R" || n == "G" || n == "B")) {

					//now look
					UObj_Offsets::dwStructOffset = i;

					sprintf_s(msg, 124, "FOUND STRUCT %04X ptr: %p \n", i, pInner.ptr);
					OutputDebugStringA(msg);
					break;
					//i -= 8;//skip next..
					//break;
				}
			}
		}
	}

	
	printf("Brute done.\n");
}

int main() {
	LuaInit();

	hProcess = NULL;
	base = 0;
#ifdef UE3
	HWND hWnd = FindWindowA("LaunchUnrealUWindowsClient", NULL);
#else
	HWND hWnd = FindWindowA("UnrealWindow", NULL);
#endif
	wchar_t cbWndName[MAX_PATH];
	GetWindowTextW(hWnd, cbWndName, MAX_PATH);
	wprintf(L"Found game: %s\n", cbWndName);

	sWndFind = cbWndName;

	//InitLastOasis();
	//InitBorderlands3();
#ifdef UE3
	InitPaladins();

#else
	if (!wcscmp(cbWndName, L"Deadside  "))
		InitDeadSide();
	else if (!wcscmp(cbWndName, L"VALORANT  "))
		InitValorant();
	//else InitPubGSteam();
	//InitPubGLite();
#endif
	//BruteStruct();

	GetBase();
	GScan();
	//printf(GetList().c_str());
	//VerifyOffsets();

	std::thread t = StartWebServer();
	OutputDebugStringA(CNames::GetName(0));

	//Here we are using PubG Steam as PoC but it should work for any UE4 Game.
	t.join();
	return 0;
}