#pragma once

template< class T > struct TArray
{
public:
	T* Data;
	int Count;
	int Max;

public:
	TArray()
	{
		Data = NULL;
		Count = Max = 0;
	};

public:
	int Num()
	{
		return this->Count;
	};

	T& operator() (int i)
	{
		return this->Data[i];
	};

	const T& operator() (int i) const
	{
		return this->Data[i];
	};

	void Add(T InputData)
	{
		Data = (T*)realloc(Data, sizeof(T) * (Count + 1));
		Data[Count++] = InputData;
		Max = Count;
	};

	void Clear()
	{
		free(Data);
		Count = Max = 0;
	};
};

struct FName
{
	int				Index;
	unsigned char	unknownData00[0x4];
};

struct FString : public TArray< wchar_t > {

};
#include <vector>
class FUObjectItem
{
public:
	enum class EInternalObjectFlags : int32_t
	{
		None = 0,
		Native = 1 << 25,
		Async = 1 << 26,
		AsyncLoading = 1 << 27,
		Unreachable = 1 << 28,
		PendingKill = 1 << 29,
		RootSet = 1 << 30,
		NoStrongReference = 1 << 31
	};
	ULONG_PTR Object; //0x0000
	__int32 Flags; //0x0008
	__int32 ClusterIndex; //0x000C
	__int32 SerialNumber; //0x0010
	__int32 SerialNumber2; //0x0010
};

class TUObjectArray {
public:
	FUObjectItem* Objects[9];
};

class GObjects {
public:
	TUObjectArray* ObjectArray;
	BYTE _padding_0[0xC];
	DWORD ObjectCount;
};

struct FPointer
{
	uintptr_t Dummy;
};
struct FQWord
{
	int A;
	int B;
};
class UClass;
class UObject
{
public:
	FPointer VTableObject;
	int32_t ObjectFlags;
	int32_t InternalIndex;
	UClass* Class;
	FName Name;
	UObject* Outer;
};
class UField : public UObject
{
public:
	UField* Next;
};
template<typename KeyType, typename ValueType>
class TPair
{
public:
	KeyType   Key;
	ValueType Value;
};

class UEnum : public UField
{
public:
	unsigned char                                      UnknownData00[0x30];                                      // 0x0030(0x0030) MISSED OFFSET
																												 //FString CppType; //0x0030 
																												 //TArray<TPair<FName, uint64_t>> Names; //0x0040 
																												 //__int64 CppForm; //0x0050 
};

class UStruct : public UField
{
public:
	UStruct* SuperField;
	UField* Children;
	int32_t PropertySize;
	int32_t MinAlignment;
	char pad_0x0048[0x40];
};
static_assert(offsetof(UStruct, SuperField) == 0x30);
static_assert(offsetof(UStruct, Children) == 0x38);
static_assert(offsetof(UStruct, Next) == 0x28);
class UFunction : public UStruct
{
public:
	__int32 FunctionFlags; //0x0088
	__int16 RepOffset; //0x008C
	__int8 NumParms; //0x008E
	char pad_0x008F[0x1]; //0x008F
	__int16 ParmsSize; //0x0090
	__int16 ReturnValueOffset; //0x0092
	__int16 RPCId; //0x0094
	__int16 RPCResponseId; //0x0096
	class UProperty* FirstPropertyToInit; //0x0098
	UFunction* EventGraphFunction; //0x00A0
	__int32 EventGraphCallOffset; //0x00A8
	void* Func; //0x00B0
};
class UScriptStruct : public UStruct
{
public:
	char pad_0x0088[0x10]; //0x0088
};

class UClass : public UStruct
{
public:
	char pad_0x0088[0x1C8]; //0x0088
};

class UProperty : public UField
{
	using UField::UField;
public:
	__int32 ArrayDim; //0x0030 
	__int32 ElementSize; //0x0034 
	FQWord PropertyFlags; //0x0038
	__int32 PropertySize; //0x0040 
	__int32 Offset; //0x0050 
	char pad_0x0044[0xC]; //0x0044
	char pad_0x0054[0x1C]; //0x0054
};
class UBoolProperty : public UProperty
{
public:
	unsigned long		BitMask;									// 0x0088 (0x04)
};
class UArrayProperty : public UProperty
{
public:
	UProperty* Inner;
};
class UMapProperty : public UProperty
{
public:
	UProperty* KeyProp;
	UProperty* ValueProp;
};
class UStructProperty : public UProperty
{
public:
	UScriptStruct* Struct;
};


static_assert(offsetof(UBoolProperty, Offset) == 0x44);
static_assert(offsetof(UBoolProperty, Offset) == 0x44);
static_assert(offsetof(UBoolProperty, Next) == 0x28);
namespace UObj_Offsets {
	DWORD dwClassOffset = 0x10;
	DWORD dwOffOffset = 0x44;
	DWORD dwActorsList = 0xA0;
	DWORD dwSuperClassOffset2 = offsetof(UStruct, SuperField);
	DWORD dwSizeOffset = offsetof(UProperty, ArrayDim);
	DWORD dwStructOffset = 0;
	DWORD dwBitmaskOffset = 0;
	DWORD dwInnerOffset = offsetof(UStructProperty, Struct);
	DWORD dwPropSize = offsetof(UStruct, PropertySize);
	DWORD dwChildOffset = offsetof(UStruct, Children);
	DWORD dwNextOffset = offsetof(UStruct, Next);
	DWORD dwNameIdOffset = offsetof(UObject, Name);
}
static_assert(offsetof(UStructProperty, Struct) == 0x70);
static_assert(offsetof(UObject, Name) == 0x18);