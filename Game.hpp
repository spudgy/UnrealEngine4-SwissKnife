#pragma once
/*OUTDATED DEC
__int64 __fastcall dec_prop(__int64 a1, char* a2)
{
	char* v2; // r13@1
	__int64 v3; // rdi@1
	unsigned __int64 v4; // r11@1
	__int64 v5; // r15@1
	signed __int64 v6; // r14@1
	unsigned __int64 v7; // r8@1
	int v8; // ebp@1
	unsigned __int64 v9; // rbx@2
	char* v10; // r10@3
	int v11; // er11@3
	unsigned int v12; // er11@3
	unsigned __int64 v13; // rdx@3
	signed __int64 v14; // rax@3
	signed __int64 v15; // rcx@3
	unsigned __int64 v16; // r9@3
	__int64 v17; // rcx@3
	unsigned __int64 v18; // rdx@3
	unsigned __int64 v19; // rcx@3
	unsigned __int64 v20; // rdx@3
	unsigned __int64 v21; // r9@3
	signed __int64 v22; // rdx@3
	__int64 v23; // rcx@3
	char* v24; // rcx@3
	__int64 v25; // rax@4
	signed __int64 v26; // rcx@5
	__int64 v27; // rax@6
	unsigned __int64 v28; // r11@7
	unsigned __int64 v29; // r14@7
	__int64 v30; // r8@7
	unsigned __int64 v31; // rbx@10
	char* v32; // r10@11
	int v33; // er11@11
	int v34; // er11@11
	int v35; // er9@11
	unsigned int v36; // edx@11
	int v37; // ecx@11
	int v38; // edx@11
	int v39; // ecx@11
	unsigned int v40; // ecx@11
	int v41; // edx@11
	int v42; // ecx@11
	int v43; // edx@11
	int v44; // ecx@11
	signed __int64 v45; // rdx@11
	char* v46; // rcx@11
	__int64 v47; // rax@12
	signed __int64 v48; // rcx@13
	__int64 v49; // rax@14
	unsigned __int64 v50; // r11@15
	unsigned __int64 v51; // r14@15
	__int64 v52; // r8@15
	unsigned __int64 v53; // r12@17
	char v54; // di@18
	char v55; // si@18
	unsigned int v56; // er11@18
	char v57; // dl@18
	char v58; // dl@18
	char v59; // cl@18
	unsigned __int64 v60; // r11@18
	char v61; // dl@18
	unsigned __int64 v62; // r14@18
	__int64 v63; // r8@18
	__int64 result; // rax@22
	__int64 v65; // [sp+50h] [bp+8h]@1

	DWORD64 _ImageBase = GetBase();
	v65 = a1;
	v2 = a2;
	v3 = a1;
	ReadTo((LPBYTE)(a1 + 0xE), a2, Read<_WORD>(a1 + 0xC));
	v4 = Read < _DWORD>(v3 + 8);
	v5 = 0i64;
	v6 = 2685821657736338717i64 * (v4 ^ (Read < _DWORD>(v3 + 8) << 25) ^ ((v4 ^ (v4 >> 15)) >> 12));
	v7 = 2685821657736338717i64
		* ((unsigned int)(v4 - 111492228) ^ (unsigned int)(((_DWORD)v4 - 4) << 25) ^ (((unsigned int)(v4 - 111492228) ^ ((unsigned __int64)(unsigned int)(v4 - 111492228) >> 15)) >> 12));
	v8 = 8 * Read < _WORD>(v3 + 12) + 1;
	if ((unsigned int)v8 >= 0x40)
	{
		v9 = (unsigned __int64)(unsigned int)v8 >> 6;
		do
		{
			v10 = &v2[(unsigned int)v5];
			v11 = __ROR4__(v4, 1);
			v12 = __ROR4__(v11, 1);
			v13 = 2i64 * ~*(_QWORD*)v10 ^ (2i64 * ~*(_QWORD*)v10 ^ (~*(_QWORD*)v10 >> 1)) & 0x5555555555555555i64;
			v14 = 4 * v13;
			v15 = (4 * v13 ^ (v13 >> 2)) & 0x3333333333333333i64;
			LODWORD(v13) = __ROR4__(v12, 1);
			LODWORD(v13) = __ROR4__(v13, 1);
			LODWORD(v13) = __ROR4__(v13, 1);
			LODWORD(v13) = __ROR4__(v13, 1);
			v16 = 16 * (v14 ^ v15) ^ (16 * (v14 ^ v15) ^ ((v14 ^ (unsigned __int64)v15) >> 4)) & 0xF0F0F0F0F0F0F0Fi64;
			v17 = __ROL8__((v16 << 8) ^ ((v16 << 8) ^ (v16 >> 8)) & 0xFF00FF00FF00FFi64, 32);
			v18 = 2 * ((unsigned int)v13 + v17) ^ (2 * ((unsigned int)v13 + v17) ^ (((unsigned __int64)(unsigned int)v13 + v17) >> 1)) & 0x5555555555555555i64;
			v19 = 2 * v18 ^ (2 * v18 ^ (v18 >> 1)) & 0x5555555555555555i64;
			v20 = 4 * v19 ^ (4 * v19 ^ (v19 >> 2)) & 0x3333333333333333i64;
			v21 = 16 * v20 ^ (16 * v20 ^ (v20 >> 4)) & 0xF0F0F0F0F0F0F0Fi64;
			v22 = 8i64;
			v23 = __ROL8__((v21 << 8) ^ ((v21 << 8) ^ (v21 >> 8)) & 0xFF00FF00FF00FFi64, 32);
			*(_QWORD*)v10 = v23;
			v24 = &v2[(unsigned int)v5];
			do
			{
				v25 = (unsigned __int8)*v24++;
				*(v24 - 1) = Read < _BYTE>(_ImageBase + v25 + 0x3C3F1D0);
				--v22;
			} while (v22);
			v26 = 8i64;
			*(_QWORD*)v10 ^= ~(unsigned __int64)v12;
			do
			{
				v27 = (unsigned __int8)*v10++;
				*(v10 - 1) = Read < _BYTE>(_ImageBase + v27 + 0x3C3F1D0);
				--v26;
			} while (v26);
			v28 = v6 + v7;
			v5 = (unsigned int)(v5 + 8);
			v29 = v7 ^ v6;
			v4 = v28 >> 32;
			v30 = __ROR8__(v7, 9);
			v8 -= 64;
			v7 = v29 ^ (v29 << 14) ^ v30;
			v6 = __ROR8__(v29, 28);
			--v9;
		} while (v9);
		v3 = v65;
	}
	if ((unsigned int)v8 >= 0x20)
	{
		v31 = (unsigned __int64)(unsigned int)v8 >> 5;
		do
		{
			v32 = &v2[(unsigned int)v5];
			v33 = __ROL4__(v4, 1);
			v34 = __ROL4__(v33, 1);
			v35 = __ROL4__(v34, 1);
			v35 = __ROL4__(v35, 1);
			v35 = __ROL4__(v35, 1);
			v35 = __ROL4__(v35, 1);
			v36 = 2 * ~*(_DWORD*)v32 ^ (2 * ~*(_DWORD*)v32 ^ ((unsigned int)~*(_DWORD*)v32 >> 1)) & 0x55555555;
			v37 = 4 * v36 ^ (4 * v36 ^ (v36 >> 2)) & 0x33333333;
			v38 = 16 * v37 ^ (16 * v37 ^ ((unsigned int)v37 >> 4)) & 0xF0F0F0F;
			v39 = __ROL4__((v38 << 8) ^ ((v38 << 8) ^ ((unsigned int)v38 >> 8)) & 0xFF00FF, 16);
			v40 = 2 * (v39 + v35) ^ (2 * (v39 + v35) ^ ((unsigned int)(v39 + v35) >> 1)) & 0x55555555;
			v41 = 2 * v40 ^ (2 * v40 ^ (v40 >> 1)) & 0x55555555;
			v42 = 4 * v41 ^ (4 * v41 ^ ((unsigned int)v41 >> 2)) & 0x33333333;
			v43 = 16 * v42 ^ (16 * v42 ^ ((unsigned int)v42 >> 4)) & 0xF0F0F0F;
			v44 = __ROL4__((v43 << 8) ^ ((v43 << 8) ^ ((unsigned int)v43 >> 8)) & 0xFF00FF, 16);
			*(_DWORD*)v32 = v44;
			v45 = 4i64;
			v46 = &v2[(unsigned int)v5];
			do
			{
				v47 = (unsigned __int8)*v46++;
				*(v46 - 1) = Read < _BYTE>(_ImageBase + v47 + 0x3C3F0D0);
				--v45;
			} while (v45);
			*(_DWORD*)v32 ^= v34;
			v48 = 4i64;
			do
			{
				v49 = (unsigned __int8)*v32++;
				*(v32 - 1) = Read < _BYTE>(_ImageBase + v49 + 63172816);
				--v48;
			} while (v48);
			v50 = v6 + v7;
			v5 = (unsigned int)(v5 + 4);
			v51 = v7 ^ v6;
			v4 = v50 >> 32;
			v52 = __ROR8__(v7, 9);
			v8 -= 32;
			v7 = v51 ^ (v51 << 14) ^ v52;
			v6 = __ROR8__(v51, 28);
			--v31;
		} while (v31);
	}
	if ((unsigned int)v8 >= 8)
	{
		v53 = (unsigned __int64)(unsigned int)v8 >> 3;
		do
		{
			v54 = 11 * v4;
			v8 -= 8;
			v55 = 51 * v4;
			v56 = 14641 * v4;
			v57 = __ROL1__(v2[v5] + 49 * v56, 1331 * v56 % 7 + 1);
			v58 = __ROR1__(~v57, 11 * v56 % 7 + 1);
			v59 = v56 % 7 + 1;
			v60 = v6 + v7;
			v61 = __ROL1__(v58, v59);
			v62 = v7 ^ v6;
			v4 = v60 >> 32;
			v63 = __ROR8__(v7, 9);
			v7 = v62 ^ (v62 << 14) ^ v63;
			v2[v5] = v61 - v54 - v55;
			v6 = __ROR8__(v62, 28);
			v5 = (unsigned int)(v5 + 1);
			--v53;
		} while (v53);
		v3 = v65;
	}
	if (v8)
		v2[v5] ^= v4 & 1;
	result = Read < _WORD>(v3 + 12);
	v2[result] = 0;
	return result;
}*/
using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using s8 = int8_t;
using s16 = int16_t;
using s32 = int32_t;
using s64 = int64_t;

u8 RITO_SBOX64[] = { 0x77, 0xB9, 0x04, 0x2F, 0xEB, 0x7D, 0x27, 0xC9, 0x44, 0x73, 0x9A, 0x3F, 0x36, 0xF5, 0x65, 0xDD,
			 0xF7, 0xE0, 0x30, 0x2D, 0xA9, 0x98, 0x5D, 0xDE, 0x69, 0xA3, 0x94, 0xA0, 0x5E, 0x17, 0x06, 0x78,
			 0xA4, 0xF6, 0xAB, 0x03, 0x43, 0xC8, 0x28, 0xE5, 0x6A, 0x8E, 0x1C, 0xF2, 0x70, 0xCF, 0x53, 0x05,
			 0xD3, 0x0D, 0xFF, 0xA7, 0xA2, 0x3A, 0x32, 0x25, 0x5A, 0x1F, 0x48, 0xC1, 0xB7, 0xE1, 0x6E, 0x85,
			 0x99, 0x60, 0x47, 0xBB, 0xE4, 0x8A, 0xCB, 0xC0, 0x1B, 0xEA, 0x61, 0x64, 0xF0, 0xC2, 0xD8, 0x8B,
			 0xCD, 0xFD, 0xAD, 0xB8, 0x19, 0xB5, 0xBF, 0x0E, 0x91, 0x81, 0x83, 0x9D, 0x45, 0xD2, 0x49, 0xE9,
			 0xC7, 0x31, 0xBD, 0x20, 0xBE, 0xC6, 0x66, 0x80, 0xD1, 0x79, 0xD7, 0xE6, 0xFC, 0xA1, 0x5B, 0x5F,
			 0xDF, 0xF1, 0xD0, 0x50, 0x67, 0x52, 0xFE, 0x7B, 0x35, 0x13, 0xF8, 0x46, 0xB3, 0x75, 0x8D, 0xE3,
			 0x3E, 0x2E, 0xF4, 0xDC, 0x34, 0x2A, 0x08, 0x23, 0xE2, 0x0C, 0x09, 0x4B, 0xEE, 0xC3, 0x0F, 0x24,
			 0x8F, 0x54, 0x4C, 0x55, 0x39, 0xCC, 0x1D, 0x1E, 0x3B, 0x22, 0x72, 0xDA, 0x29, 0x6B, 0x41, 0xAA,
			 0xA6, 0x12, 0x2C, 0x93, 0xCA, 0x9C, 0x97, 0x0A, 0x56, 0xA8, 0x7A, 0x9E, 0xB4, 0x62, 0x92, 0x3D,
			 0x9F, 0x38, 0xF3, 0x40, 0x84, 0x37, 0xB2, 0xD4, 0xAF, 0x76, 0x33, 0xFA, 0x21, 0xEF, 0xFB, 0x71,
			 0x6F, 0x90, 0x82, 0x51, 0x1A, 0xC5, 0x74, 0xF9, 0x59, 0x07, 0xBA, 0x11, 0xB1, 0xAC, 0xD6, 0xED,
			 0xE7, 0x02, 0xAE, 0x96, 0x10, 0x16, 0x7C, 0x4F, 0x88, 0x14, 0x26, 0xBC, 0x15, 0x01, 0x68, 0x4A,
			 0x2B, 0x0B, 0x7F, 0xA5, 0x4E, 0xE8, 0x6D, 0xEC, 0x4D, 0xB0, 0x5C, 0xC4, 0x00, 0x95, 0x58, 0xB6,
			 0xD5, 0x7E, 0x42, 0xDB, 0x57, 0x18, 0x86, 0x6C, 0xCE, 0xD9, 0x9B, 0x89, 0x87, 0x3C, 0x8C, 0x63 };

u8 RITO_SBOX32[] = { 0x21, 0x67, 0xB3, 0x96, 0x31, 0x3F, 0xBA, 0xD3, 0xD5, 0x06, 0x2B, 0x16, 0xF1, 0xB6, 0x51, 0xA7,
			 0x9C, 0x7B, 0x41, 0x95, 0x84, 0x25, 0x15, 0x36, 0xA4, 0x70, 0x35, 0x46, 0xB0, 0x5F, 0xA6, 0xC3,
			 0xBB, 0x86, 0x38, 0xF6, 0x2E, 0xA2, 0xA9, 0x94, 0x83, 0x1B, 0x62, 0x39, 0xF3, 0xD2, 0x28, 0x14,
			 0x9E, 0x9A, 0xF2, 0xC9, 0xDE, 0xCC, 0x26, 0xA1, 0xD8, 0xD0, 0x74, 0x8D, 0x69, 0x12, 0x71, 0x89,
			 0xF7, 0x58, 0xCD, 0x4D, 0xB7, 0x11, 0x48, 0x09, 0xB9, 0x68, 0xC7, 0x7C, 0xF4, 0x20, 0x42, 0xF5,
			 0x6B, 0x54, 0x75, 0x6D, 0xA8, 0x1D, 0x6A, 0x07, 0xD7, 0xC5, 0x0E, 0xA0, 0x66, 0xDB, 0xF8, 0x99,
			 0xAD, 0x10, 0x04, 0xFF, 0x8F, 0xB1, 0xEF, 0x98, 0x6C, 0x29, 0xE2, 0x01, 0x18, 0x3D, 0x37, 0x1E,
			 0x65, 0x4B, 0x4A, 0x6E, 0x24, 0xD9, 0xBD, 0x90, 0xFE, 0x13, 0x56, 0x93, 0x34, 0xAA, 0x8B, 0x0D,
			 0x79, 0xE7, 0x49, 0x92, 0xF9, 0x8E, 0xCA, 0x43, 0xCB, 0xC6, 0xDA, 0x02, 0x2D, 0x8C, 0x0F, 0xB2,
			 0xC0, 0x8A, 0x47, 0x85, 0xAE, 0xE0, 0xD4, 0x77, 0xC4, 0x0B, 0x5C, 0x61, 0x7E, 0x33, 0x57, 0x45,
			 0xE6, 0x2F, 0xFD, 0x6F, 0x91, 0x5B, 0x9F, 0xCF, 0x3C, 0x4F, 0xE3, 0x3A, 0xED, 0xE4, 0x80, 0x08,
			 0x73, 0x72, 0xEA, 0x63, 0xFB, 0xFC, 0xB8, 0x7A, 0x23, 0xA5, 0x1F, 0x81, 0x59, 0x52, 0x87, 0x5D,
			 0xFA, 0x78, 0xC1, 0xB5, 0xBE, 0xB4, 0xA3, 0x64, 0x1C, 0x32, 0x53, 0xF0, 0x7F, 0xDC, 0x3B, 0x76,
			 0x40, 0xEC, 0x30, 0x97, 0x55, 0x4C, 0x00, 0xBC, 0x88, 0x0C, 0x05, 0xE1, 0xDF, 0x19, 0x7D, 0x22,
			 0xC2, 0x5A, 0x9B, 0xE5, 0x2A, 0x50, 0xBF, 0x1A, 0xC8, 0x03, 0x5E, 0x2C, 0xD1, 0xAB, 0xDD, 0x44,
			 0xEE, 0x82, 0xCE, 0x27, 0xAF, 0xEB, 0xD6, 0x4E, 0x0A, 0xE9, 0x17, 0x3E, 0x9D, 0xE8, 0xAC, 0x60 };


struct RitoState {
	u8* d;	       // Data pointer
	u64 k, y1, y2; // State keys
	u32 b;	       // Bits remaining

	RitoState(u8* data, u64 key, u32 len) {
		d = data;
		k = key;
		b = (len * 8) + 1;

		u32 t = (u32)(k - 0x6A53C84);
		static const u64 seed = 0x2545F4914F6CDD1DULL;
		y1 = seed * (u32)((k ^ (k << 25) ^ ((k ^ (k >> 15)) >> 12)));
		y2 = seed * (u32)((t ^ (t << 25) ^ ((t ^ (t >> 15)) >> 12)));
	}
};

#define RITO_CPY_BOX( s, c, b )                                                                                        \
	{                                                                                                              \
		for ( s32 i = 0; i < c; i++ )                                                                          \
			s.d[ i ] = b[ s.d[ i ] ];                                                                      \
	}

#define RITO_DEC_64( s )                                                                                               \
	{                                                                                                              \
		u64 k64 = __ROR4__( __ROR4__( ( u32 ) s.k, 1 ), 1 );													\
		u64* d64 = ( u64* ) s.d;                                                                               \
		u64 x0 = ~( *d64 );                                                                                    \
		u64 x1 = ( x0 << 1 ) ^ ( ( x0 << 1 ) ^ ( x0 >> 1 ) ) & 0x5555555555555555ULL;                          \
		u64 x2 = ( x1 << 2 ) ^ ( ( x1 << 2 ) ^ ( x1 >> 2 ) ) & 0x3333333333333333ULL;                          \
		u64 x3 = ( x2 << 4 ) ^ ( ( x2 << 4 ) ^ ( x2 >> 4 ) ) & 0x0F0F0F0F0F0F0F0FULL;                          \
		u64 x4 = ( x3 << 8 ) ^ ( ( x3 << 8 ) ^ ( x3 >> 8 ) ) & 0x00FF00FF00FF00FFULL;                          \
		u64 x5 = __ROL8__( x4, 32 ) + __ROR4__( ( u32 ) k64, 4 );                                              \
		u64 x6 = ( x5 << 1 ) ^ ( ( x5 << 1 ) ^ ( x5 >> 1 ) ) & 0x5555555555555555ULL;                          \
		u64 x7 = ( x6 << 1 ) ^ ( ( x6 << 1 ) ^ ( x6 >> 1 ) ) & 0x5555555555555555ULL;                          \
		u64 x8 = ( x7 << 2 ) ^ ( ( x7 << 2 ) ^ ( x7 >> 2 ) ) & 0x3333333333333333ULL;                          \
		u64 x9 = ( x8 << 4 ) ^ ( ( x8 << 4 ) ^ ( x8 >> 4 ) ) & 0x0F0F0F0F0F0F0F0FULL;                          \
		u64 xA = ( x9 << 8 ) ^ ( ( x9 << 8 ) ^ ( x9 >> 8 ) ) & 0x00FF00FF00FF00FFULL;                          \
		*d64 = __ROL8__( xA, 32 );                                                                             \
		RITO_CPY_BOX( s, 8, RITO_SBOX64 )                                                                      \
		*d64 ^= ~k64;                                                                                          \
		RITO_CPY_BOX( s, 8, RITO_SBOX64 )                                                                      \
	}

#define RITO_DEC_32( s )                                                                                               \
	{                                                                                                              \
		u32 k32 = __ROL4__( __ROL4__( ( u32 ) s.k, 1 ), 1 );                                                   \
		u32* d32 = ( u32* ) s.d;                                                                               \
		u32 x0 = ~( *d32 );                                                                                    \
		u32 x1 = ( x0 << 1 ) ^ ( ( x0 << 1 ) ^ ( x0 >> 1 ) ) & 0x55555555;                                     \
		u32 x2 = ( x1 << 2 ) ^ ( ( x1 << 2 ) ^ ( x1 >> 2 ) ) & 0x33333333;                                     \
		u32 x3 = ( x2 << 4 ) ^ ( ( x2 << 4 ) ^ ( x2 >> 4 ) ) & 0x0F0F0F0F;                                     \
		u32 x4 = ( x3 << 8 ) ^ ( ( x3 << 8 ) ^ ( x3 >> 8 ) ) & 0x00FF00FF;                                     \
		u32 x5 = __ROL4__( x4, 16 ) + __ROL4__( k32, 4 );                                                      \
		u32 x6 = ( x5 << 1 ) ^ ( ( x5 << 1 ) ^ ( x5 >> 1 ) ) & 0x55555555;                                     \
		u32 x7 = ( x6 << 1 ) ^ ( ( x6 << 1 ) ^ ( x6 >> 1 ) ) & 0x55555555;                                     \
		u32 x8 = ( x7 << 2 ) ^ ( ( x7 << 2 ) ^ ( x7 >> 2 ) ) & 0x33333333;                                     \
		u32 x9 = ( x8 << 4 ) ^ ( ( x8 << 4 ) ^ ( x8 >> 4 ) ) & 0x0F0F0F0F;                                     \
		u32 xA = ( x9 << 8 ) ^ ( ( x9 << 8 ) ^ ( x9 >> 8 ) ) & 0x00FF00FF;                                     \
		*d32 = __ROL4__( xA, 16 );                                                                             \
		RITO_CPY_BOX( s, 4, RITO_SBOX32 )                                                                      \
		*d32 ^= k32;                                                                                           \
		RITO_CPY_BOX( s, 4, RITO_SBOX32 )                                                                      \
	}

#define RITO_DEC_8( s )                                                                                                \
	{                                                                                                              \
		s8 x0 = ( s8 )( 0x0B * s.k );                                                                          \
		s8 x1 = ( s8 )( 0x33 * s.k );                                                                          \
		u32 x2 = ( u32 )( 0x3931 * s.k );                                                                      \
		s8 x3 = __ROR1__( ~__ROL1__( *s.d + 0x31 * x2, 0x533 * x2 % 7 + 1 ), 0x0B * x2 % 7 + 1 );              \
		*s.d = __ROL1__( x3, x2 % 7 + 1 ) - x0 - x1;                                                           \
	}

#define RITO_KEY_ROT( s, c )                                                                                           \
	{                                                                                                              \
		u64 yx = s.y1 ^ s.y2;                                                                                  \
		s.k = ( s.y1 + s.y2 ) >> 32;                                                                           \
		s.y2 = yx ^ ( yx << 14 ) ^ __ROR8__( s.y2, 9 );                                                        \
		s.y1 = __ROR8__( yx, 28 );                                                                             \
		s.d += c;                                                                                              \
		s.b -= c * 8;                                                                                          \
	}

void rito_decrypt_name(u8* dest, u32 key, u8* src, u32 len) {
	// Copy the crypted data
	memcpy(dest, src, len);

	// Initialize the rito state
	RitoState s(dest, key, len);

	// Decode the 64 bit blocks
	while (s.b >= 64) {
		RITO_DEC_64(s);
		RITO_KEY_ROT(s, 8);
	}

	// Decode the 32 bit blocks
	while (s.b >= 32) {
		RITO_DEC_32(s);
		RITO_KEY_ROT(s, 4);
	}

	// Decode the 8 bit blocks
	while (s.b >= 8) {
		RITO_DEC_8(s);
		RITO_KEY_ROT(s, 1);
	}

	// Decode the last bit
	if (s.b)
		*s.d ^= s.k & 1;

	// Null the last character
	dest[len] = 0;
}

#pragma pack( push, 1 )
struct FNameEntry {
	u64 pad;
	u32 seed;
	u16 len;
	u8 data[81];
};

void InitValorant() {


	/*getNameFnc = [](DWORD id) {

		static char pBuff[1024];

		LPBYTE pGNames = Read<LPBYTE>((LPBYTE)GetBase() + 0x5CB1728);// 0x5CA7C68); //look for "RootComponent" string
		if (id > Read<DWORD>(pGNames + 0x800)) return "";
		auto gengRoot = Read<DWORD64>(pGNames + 8 * (id / 0x4000));
		auto genPtr = Read<DWORD64>(gengRoot + 8 * (id % 0x4000));
		dec_prop(genPtr, pBuff);
		return (const char*)pBuff;
	};*/
	getNameFnc = [](DWORD id) {

		FNameEntry entry;
		static char pBuff[1024];

		// 48 8B 05 ? ? ? ? 48 85 C0 75 64
		LPBYTE pGNames = Read<LPBYTE>((LPBYTE)GetBase() + 0x5CB1728); //look for "RootComponent" string
		if (id > Read<DWORD>(pGNames + 0x800)) return "";
		auto gengRoot = Read<DWORD64>(pGNames + 8 * (id / 0x4000));
		auto pGenPtr = Read<DWORD64>(gengRoot + 8 * (id % 0x4000));

		FNameEntry genPtr;
		ReadTo((LPVOID)(pGenPtr), &genPtr, (int)sizeof(FNameEntry));
		//dec_prop(genPtr, pBuff);

		rito_decrypt_name((u8*)pBuff, genPtr.seed, genPtr.data, genPtr.len);
		pBuff[genPtr.len] = 0;


		return (const char*)pBuff;
	};

	sWndFind = L"VALORANT  ";
	UObj_Offsets::dwSuperClassOffset2 = 0x48;
	UObj_Offsets::dwChildOffset = 0x50;//
	UObj_Offsets::dwNextOffset = 0x30;
	UObj_Offsets::dwSizeOffset = 0x38;//?
	UObj_Offsets::dwOffOffset = 0x4C;
	UObj_Offsets::dwInnerOffset = 0x80;
	UObj_Offsets::dwStructOffset = 0x70;
	UObj_Offsets::dwPropSize = 0x58;

	UObj_Offsets::dwBitmaskOffset = 0x82;

	ENGINE_OFFSET = 0x5DD6130;// 0x5DCC670; //48 8B 0D ?? ?? ?? ?? 48 85 C9 74 1E 48 8B 01 FF 90
	extern DWORD64 gObj;
	gObj = GetBase() + 0x5CAC308;
	//0x5CAC308 //GOBJ
	GetBase();
	GScan();

	//printf("mat: %p\n", FindObject("AK_Luxury_MI", 0x280003));
}