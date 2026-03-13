#include <Windows.h>
#include "pentane.hpp"
#include <sunset/sunset.hpp>
#include <cstdint>
#include <string>

void(*Pentane_LogUTF8)(PentaneCStringView*) = nullptr;

// meta
#pragma comment(linker, "/EXPORT:Pentane_PluginInformation=_Pentane_PluginInformation")
extern "C" PluginInformation Pentane_PluginInformation = {
    .name    = "Extended Character Limit",
    .author  = "Cassinni4",
    .uuid    = { 0x1c, 0x5b, 0x7a, 0x3d, 0xe2, 0x90, 0x4f, 0x68,
                 0xb3, 0x71, 0xd8, 0x4e, 0x05, 0xca, 0x29, 0xf1 },
    .version = SemVer{ 0, 5, 0 },
    .minimum_pentane_version = SemVer{ 0, 1, 0 },
};
#pragma comment(linker, "/EXPORT:Pentane_PluginDependencyCount=_Pentane_PluginDependencyCount")
extern "C" int Pentane_PluginDependencyCount = 0;
#pragma comment(linker, "/EXPORT:Pentane_PluginDependencies=_Pentane_PluginDependencies")
extern "C" PentaneUUID* Pentane_PluginDependencies = nullptr;

static constexpr uint32_t NEW_CHAR_LIMIT  = 0x1F4; // 500
static constexpr uint32_t ORIG_CHAR_LIMIT = 0x154; // 340

static constexpr uintptr_t ADDR_CHAR_COUNT      = 0x0093B278;
static constexpr uintptr_t ADDR_CHAR_LIMIT_CTRL = 0x0086E4E0;
static constexpr uint32_t  CAVE2_BYTE_END       = 0x086E70A;

static inline uint32_t char_count() {
    return *reinterpret_cast<uint32_t*>(ADDR_CHAR_COUNT);
}

static uint16_t* g_buf_a      = nullptr;
static uint16_t* g_buf_b      = nullptr;
static uint8_t*  g_buf_c      = nullptr;
static uint8_t*  g_type_flags = nullptr;
static uint8_t*  g_cnt_flags  = nullptr;
static short*    g_freeplay_buf = nullptr;

static uintptr_t FileOffsetToVA(uintptr_t file_offset) {
    const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (file_offset >= sec->PointerToRawData &&
            file_offset <  sec->PointerToRawData + sec->SizeOfRawData)
            return base + sec->VirtualAddress + (file_offset - sec->PointerToRawData);
    }
    return 0;
}

static void PatchU16(uintptr_t file_offset, uint16_t value) {
    const uintptr_t va = FileOffsetToVA(file_offset);
    if (!va) {
        logger::log("[Extended Character Limit] WARNING: PatchU16 failed for 0x" + std::to_string(file_offset));
        return;
    }
    const auto old = sunset::utils::set_permission(
        reinterpret_cast<void*>(va), 2, sunset::utils::Perm::ExecuteReadWrite).unwrap();
    *reinterpret_cast<uint16_t*>(va) = value;
    sunset::utils::set_permission(reinterpret_cast<void*>(va), 2, old);
}

// siberys the goat
static void __cdecl Cave1_Handler(uint32_t eax_in, uint32_t ecx, uint32_t edx) {
    const uint16_t fill_val = *reinterpret_cast<const uint16_t*>(edx);
    uint16_t* const dst = (ecx == 0x0019FB70) ? g_buf_a : g_buf_b;
    if (!dst) return;

    const uintptr_t dst_base = reinterpret_cast<uintptr_t>(dst);
    const uint32_t  total    = char_count();
    uint32_t edi = 0;
    for (uint32_t cur = eax_in; cur < total; ++cur, ++edi)
        dst[edi] = fill_val;

    auto mark_special = [&](uintptr_t addr_of_id) {
        const int32_t id = *reinterpret_cast<const int32_t*>(addr_of_id);
        if (id != -1)
            *reinterpret_cast<uint16_t*>(dst_base + static_cast<uint32_t>(id) * 2) = 0xFFFF;
    };
    mark_special(0x007F18FC); mark_special(0x007F1910); mark_special(0x007F1958);
    mark_special(0x007F18C4); mark_special(0x007F18E4); mark_special(0x007F18E8);
    mark_special(0x007F1A74); mark_special(0x007F1900); mark_special(0x007F19DC);
    mark_special(0x007F17C4);

    const int32_t   struct_count = *reinterpret_cast<const int32_t*> (0x0093D500);
    const uintptr_t struct_base  = *reinterpret_cast<const uintptr_t*>(0x0093D504);
    if (struct_count > 0 && struct_base != 0) {
        const auto* p = reinterpret_cast<const int16_t*>(struct_base + 0x1064);
        for (int32_t i = 0; i < struct_count; ++i, p += 0x86C) {
            const uint8_t flag = *reinterpret_cast<const uint8_t*>(reinterpret_cast<uintptr_t>(p) - 0x1468);
            if ((flag & 1) != 0)
                *reinterpret_cast<uint16_t*>(dst_base + *p * 2) = 0xFFFF;
        }
    }
}

__declspec(naked) static void Cave1_Trampoline() {
    __asm {
        pushad
        cmp  eax, 0x154
        jl   cave1_normal
        push edx
        push ecx
        push eax
        call Cave1_Handler
        add  esp, 12
        popad
        push 0x0049164C
        ret
    cave1_normal:
        popad
        mov  dx, word ptr [edx+eax*2]
        mov  word ptr [ecx+eax*2], dx
        push 0x00491641
        ret
    }
}

static void __cdecl Cave2_Handler(uint32_t eax, uint32_t esi) {
    if (!g_buf_c) return;
    uint32_t idx = 0;
    for (uint32_t cur = eax; cur < CAVE2_BYTE_END && idx < NEW_CHAR_LIMIT; ++cur, ++idx)
        g_buf_c[idx] = *reinterpret_cast<const uint8_t*>(esi + cur);
}

__declspec(naked) static void Cave2_Trampoline() {
    __asm {
        pushad
        mov  ecx, dword ptr ds:[0x0086E4E0]
        cmp  eax, ecx
        jne  cave2_skip
        push esi
        push eax
        call Cave2_Handler
        add  esp, 8
    cave2_skip:
        popad
        mov  dl, byte ptr [esi+eax]
        sub  ecx, 1
        push 0x004EF686
        ret
    }
}

static void __cdecl Cave3_Handler(int32_t edx_val) {
    if (!g_type_flags || !g_cnt_flags) return;
    if (g_cnt_flags[0x14E] <= 3) {
        const uint32_t slot = static_cast<uint32_t>(edx_val);
        if (slot < NEW_CHAR_LIMIT) g_type_flags[slot] = 3;
    }
}

__declspec(naked) static void Cave3_Trampoline() {
    __asm {
        pushad
        movsx edx, word ptr [esi+eax]
        cmp   edx, 0x14A
        jne   cave3_skip
        push  edx
        call  Cave3_Handler
        add   esp, 4
    cave3_skip:
        popad
        movsx edx, word ptr [esi+eax]
        push  edx
        push  0x0042B10D
        ret
    }
}

static void __cdecl Cave4_Handler() {
    if (!g_type_flags || !g_cnt_flags || !g_buf_c) return;
    const uint8_t bl        = *reinterpret_cast<const uint8_t*>(ADDR_CHAR_LIMIT_CTRL);
    const uint8_t secondary = g_cnt_flags[0];
    auto store = [&]() {
        *reinterpret_cast<uint16_t*>(&g_cnt_flags[0]) =
            *reinterpret_cast<const uint16_t*>(ADDR_CHAR_LIMIT_CTRL);
    };
    if (bl == g_buf_c[0] || bl <= secondary) { store(); return; }
    uint8_t rem = bl - secondary;
    for (uint32_t edi = 0; rem != 0 && edi < NEW_CHAR_LIMIT; ++edi)
        if (g_type_flags[edi] == 0) { g_type_flags[edi] = 3; --rem; }
    store();
}

__declspec(naked) static void Cave4_Trampoline() {
    __asm {
        pushad
        call Cave4_Handler
        popad
        push ebp
        xor  eax, eax
        push esi
        push edi
        push 0x0042B087
        ret
    }
}


// FUN_004890e0: __fastcall(ecx_ignored, int edx_charID)
//   - adds edx_charID to the character selection list (DAT_0087a840).
//   - param_1/ECX is declared undefined4 in ghid and never read by the function.
//   - returns 1 if added, 0 if already present / list full / charID == -1.
//
// FUN_00594b70: filters a character list by criteria, writes matching IDs to the output buffer (param_4), returns the count written.
//   ghid shows 6 params but the call site in FUN_00489150 passes 7.
//   declared with 7 here to match the call site; __cdecl so extra arg is harmless.
static auto FUN_004890e0 = reinterpret_cast<int(__fastcall*)(int /*ecx_unused*/, int /*edx_charID*/)>(0x004890E0);
static auto FUN_00594b70 = reinterpret_cast<int (__cdecl*)(void*,uint32_t,uint32_t,short*,int*,int*,int)>(0x00594B70);
static auto FUN_0055be20 = reinterpret_cast<int (__cdecl*)(void*,int,int,int,int)>    (0x0055BE20);
static auto FUN_0055bef0 = reinterpret_cast<int (__cdecl*)(int,int,int,int,int)>      (0x0055BEF0);
static auto FUN_00488ed0 = reinterpret_cast<int (__cdecl*)()>                         (0x00488ED0);
static auto FUN_00488f60 = reinterpret_cast<int (__cdecl*)(void*)>                    (0x00488F60);
static auto FUN_00594960 = reinterpret_cast<int (__cdecl*)(int)>                      (0x00594960);

// TCS globals
#define TCS_REF(type, addr) (*reinterpret_cast<type*>(addr))
static auto& DAT_0087b02c   = TCS_REF(int,       0x0087B02C);
static auto& DAT_0087b2c4   = TCS_REF(int,       0x0087B2C4);
static auto& DAT_0087a904   = TCS_REF(int,       0x0087A904);
static auto& DAT_0087a954   = TCS_REF(int,       0x0087A954);
static auto& DAT_007f39e4   = TCS_REF(int,       0x007F39E4);
static auto& DAT_0087950c   = TCS_REF(int,       0x0087950C);
static auto& DAT_007fa190   = TCS_REF(int,       0x007FA190);
static auto& DAT_007fa138   = TCS_REF(int,       0x007FA138);
static auto& DAT_00951354   = TCS_REF(uintptr_t, 0x00951354);
static auto& DAT_00951364   = TCS_REF(uintptr_t, 0x00951364);
static auto& DAT_0087a9c8   = TCS_REF(int,       0x0087A9C8);
static auto& DAT_0093d590   = TCS_REF(short,     0x0093D590);
static auto& DAT_0093d592   = TCS_REF(short,     0x0093D592);
static auto& _DAT_0093d594  = TCS_REF(uint16_t,  0x0093D594);
static auto& DAT_0093d7f0   = TCS_REF(int,       0x0093D7F0);
static auto& DAT_00855f24   = TCS_REF(int,       0x00855F24);
static auto& PTR_DAT_00802c54 = TCS_REF(uint8_t*, 0x00802C54);
static auto& DAT_00876580   = TCS_REF(int,       0x00876580);
static auto& DAT_0093b280   = TCS_REF(uintptr_t, 0x0093B280);
static auto& DAT_0093b26c   = TCS_REF(int,       0x0093B26C);
static auto& DAT_0093b274   = TCS_REF(uintptr_t, 0x0093B274);
static auto& DAT_0087a840   = TCS_REF(int,       0x0087A840);
static auto& PTR_DAT_007f17d8 = TCS_REF(short*,  0x007F17D8);
static auto& PTR_DAT_007f17dc = TCS_REF(void*,   0x007F17DC);

static auto& DAT_007f1a24 = TCS_REF(short, 0x007F1A24);
static auto& DAT_007f1a1c = TCS_REF(short, 0x007F1A1C);
static auto& DAT_007f1960 = TCS_REF(short, 0x007F1960);
static auto& DAT_007f1a28 = TCS_REF(short, 0x007F1A28);
static auto& DAT_007f19a4 = TCS_REF(short, 0x007F19A4);
static auto& DAT_007f1970 = TCS_REF(short, 0x007F1970);
static auto& DAT_007f1a2c = TCS_REF(short, 0x007F1A2C);
static auto& DAT_007f196c = TCS_REF(short, 0x007F196C);
static auto& DAT_007f1964 = TCS_REF(short, 0x007F1964);
static auto& DAT_007f1a9c = TCS_REF(short, 0x007F1A9C);
static auto& DAT_007f195c = TCS_REF(short, 0x007F195C);
static auto& DAT_007f1b2c = TCS_REF(short, 0x007F1B2C);
static auto& DAT_007f19e4 = TCS_REF(short, 0x007F19E4);
static auto& DAT_007f1b34 = TCS_REF(short, 0x007F1B34);
static auto& DAT_007f1a00 = TCS_REF(short, 0x007F1A00);
static auto& DAT_007f1b3c = TCS_REF(short, 0x007F1B3C);
static auto& DAT_007f19e8 = TCS_REF(short, 0x007F19E8);
static auto& DAT_007f1b1c = TCS_REF(short, 0x007F1B1C);
static auto& DAT_007f1a98 = TCS_REF(short, 0x007F1A98);
static auto& DAT_007f1b44 = TCS_REF(short, 0x007F1B44);
static auto& DAT_007f1b40 = TCS_REF(short, 0x007F1B40);

// FreeplayCharacterSelection
DefineReplacementHook(FreeplayCharacterSelection) {
    static void __cdecl callback(int param_1, int param_2, uint32_t param_3) {
        short* local_2ac = g_freeplay_buf; // heap replaces stack array

        int iVar4 = DAT_0087b02c;
        uint32_t uVar7;

        if ((PTR_DAT_00802c54 == nullptr ||
             *reinterpret_cast<int*>        (PTR_DAT_00802c54 + 300) == 0 ||
             *reinterpret_cast<uintptr_t*>  (PTR_DAT_00802c54 + 300) != DAT_00951364) ||
            DAT_0087950c == 0) {
            uVar7 = 0;
        } else {
            uVar7 = *reinterpret_cast<uint32_t*>(
                reinterpret_cast<uintptr_t>(&DAT_007fa138) + DAT_007fa190 * 0xc);
        }

        DAT_0087b2c4 = 0;
        DAT_0087a904 = 0;
        DAT_0087a954 = 0;
        if (param_1 == -1) param_2 = -1;

        int local_2b4[2] = { param_1, param_2 };

        if ((DAT_007f39e4 == 0 || DAT_0087b02c == 0) ||
            param_3 != *reinterpret_cast<uint8_t*>(DAT_0087b02c + 0x7c)) {

            int iVar10 = 0;
            if ((*(uint8_t*)(param_3 * 0x9c + 0x7a + DAT_00951354) & 5) == 5) {
                // !!!!!!!!!!! CALL A !!!!!!!!!!!
                // add player slot chars from local_2b4
                do {
                    if (local_2b4[iVar10] != -1)
                        FUN_004890e0(0, local_2b4[iVar10]);
                    iVar10++;
                } while (iVar10 < 2);

                FUN_00594b70(&DAT_00855f24, 0x4000000, 0x4000000, local_2ac,
                             nullptr, nullptr, DAT_0087a9c8 != 0);
                iVar10 = 0;
                iVar4  = DAT_0087b02c;
                short sVar2 = local_2ac[0];
                // !!!!!!!!!!! CALL B !!!!!!!!!!!
                // add chars written by FUN_00594b70
                while (DAT_0087b02c = iVar4, sVar2 != -1) {
                    FUN_004890e0(0, (int)sVar2);
                    iVar10++;
                    iVar4 = DAT_0087b02c;
                    sVar2 = local_2ac[iVar10];
                }
                if (DAT_0087b2c4 == 1) DAT_0093d592 = DAT_0093d590;
                _DAT_0093d594 = 0xffff;
            } else {
                // !!!!!!!!!!! CALL C !!!!!!!!!!!
                // LAB_00489300 — two player slots (si = 0, 4):
                //   if param != -1: call FUN_004890e0 with that param directly.
                //   if param == -1: read pointer from DAT_0093d7f0[si/4].
                //     if null: skip. else: use *(short*)(ptr + 0x1064) as charID.
                for (int si = 0; si < 8; si += 4) {
                    int charID = *reinterpret_cast<int*>(
                        reinterpret_cast<uintptr_t>(local_2b4) + si);
                    if (charID != -1) {
                        FUN_004890e0(0, charID);
                    } else {
                        uintptr_t fallback_ptr = *reinterpret_cast<uintptr_t*>(
                            reinterpret_cast<uintptr_t>(&DAT_0093d7f0) + si);
                        if (fallback_ptr != 0) {
                            int fallbackID = (int)*reinterpret_cast<short*>(
                                fallback_ptr + 0x1064);
                            FUN_004890e0(0, fallbackID);
                        }
                        // else: skip (matches JZ LAB_0048931f)
                    }
                }
                if (DAT_0087b2c4 == 1) {
                    DAT_0093d592 = DAT_0093d590;
                    _DAT_0093d594 = 0xffff;
                } else {
                    (&DAT_0093d590)[DAT_0087b2c4] = 0xffff;
                }
            }
        } else {
            // !!!!!!!!!!! CALL D !!!!!!!!!!!
            // six specific MOVSX EDX, [addr] ; CALL FUN_004890e0 pairs.
            static const uintptr_t kVehicleSlots[6] = {
                0x007F17D0, 0x007F1AAC, 0x007F1AB0,
                0x007F1AB4, 0x007F1AB8, 0x007F1ABC,
            };
            for (int i = 0; i < 6; i++)
                FUN_004890e0(0, (int)*reinterpret_cast<short*>(kVehicleSlots[i]));
        }
        // !!!!!!!!!!! CALL E !!!!!!!!!!!
        // add partner chars from the per-character partner list
        if (param_3 != 0xffffffff && (uVar7 & 8) == 0) {
            auto* psVar6 = *reinterpret_cast<short**>(param_3 * 0x9c + 0x98 + DAT_00951354);
            if (psVar6 != nullptr) {
                short sVar2 = *psVar6;
                while (sVar2 != -1) {
                    FUN_004890e0(0, (int)sVar2);
                    DAT_0087a904++;
                    psVar6++;
                    sVar2 = *psVar6;
                }
            }
        }

        int iVar10;
        if ((DAT_007f39e4 == 0 || iVar4 == 0) ||
            (iVar10 = DAT_0087a954, param_3 != *reinterpret_cast<uint8_t*>(iVar4 + 0x7c))) {

            uint16_t uVar3 = *reinterpret_cast<uint16_t*>(DAT_00951354 + 0x7a + param_3 * 0x9c);

            if ((uVar3 & 1) == 0) {
                iVar4  = FUN_0055be20(&DAT_0087a840, 0, 0, 1, 0);

                if (DAT_007f39e4 == 0 && DAT_00876580 == 0) {
                    // !!!!!!!!!!! CALL F !!!!!!!!!!!
                    // 004895d0: MOVSX EDX, word ptr [DAT_007f17b8]
                    iVar10 = FUN_004890e0(0, (int)*reinterpret_cast<short*>(0x007F17B8));
                    if (iVar10 != 0) DAT_0087a954++;

                    // !!!!!!!!!!! CALL G !!!!!!!!!!!
                    // 004895e6: MOVSX EDX, word ptr [DAT_007f180c]
                    iVar10 = FUN_004890e0(0, (int)*reinterpret_cast<short*>(0x007F180C));
                    if (iVar10 != 0) DAT_0087a954++;
                }
                iVar10 = DAT_0087a954;

                if (DAT_0093b280 != 0) {
                    iVar10 = 0;
                    if (DAT_0093b26c > 0) {
                        int iVar8 = 0;
                        do {
                            int iVar5 = FUN_0055be20(
                                &DAT_0087a840,
                                *reinterpret_cast<int*>(DAT_0093b280 + 4 + iVar8),
                                *reinterpret_cast<int*>(DAT_0093b280 + 8 + iVar8),
                                0, 1);
                            if (iVar5 == 0) {
                                bool cond = (iVar4 == 0) ||
                                    (DAT_007f39e4 != 0 &&
                                     (*reinterpret_cast<uint8_t*>(DAT_0093b280 + 4 + iVar8) & 0x80) != 0);
                                if (cond) {
                                    iVar5 = FUN_0055bef0(
                                        *reinterpret_cast<int*>(DAT_0093b280 + 4 + iVar8),
                                        *reinterpret_cast<int*>(DAT_0093b280 + 8 + iVar8),
                                        1, 0, 1);
                                    if (iVar5 != -1) iVar4 = 1;
                                    else goto try_bef0_fallback;
                                } else {
                                try_bef0_fallback:
                                    iVar5 = FUN_0055bef0(
                                        *reinterpret_cast<int*>(DAT_0093b280 + 4 + iVar8),
                                        *reinterpret_cast<int*>(DAT_0093b280 + 8 + iVar8),
                                        0, 0, 1);
                                    if (iVar5 == -1) goto next_iter;
                                }
                                // !!!!!!!!!!! CALL H !!!!!!!!!!!
                                // 004896a2: MOV EDX, EAX; CALL FUN_004890e0
                                // EAX is the return value of whichever FUN_0055bef0 branch fired above. iVar5 holds that value.
                                iVar5 = FUN_004890e0(0, iVar5);
                                if (iVar5 != 0) DAT_0087a954++;
                            }
                        next_iter:
                            iVar10++;
                            iVar8 += 0xc;
                        } while (iVar10 < DAT_0093b26c);
                    }
                    iVar4  = FUN_00488ed0();
                    iVar10 = DAT_0087a954;
                    if (iVar4 == 0) {
                        // !!!!!!!!!!! CALL I !!!!!!!!!!!
                        // add char returned by FUN_00488f60.
                        // FUN_00488f60 returns a character index or -1.
                        // FUN_004890e0 already returns 0 for -1, so this is safe.
                        iVar4  = FUN_00488f60(&DAT_0087a840);
                        iVar10 = DAT_0087a954;
                        if (iVar4 != -1) {
                            iVar4  = FUN_004890e0(0, iVar4);
                            iVar10 = DAT_0087a954;
                            if (iVar4 != 0) { DAT_0087a954++; iVar10 = DAT_0087a954; }
                        }
                    }
                }
            } else if ((uVar3 & 4) == 0) {
                if (DAT_0093d592 == -1 ||
                    (*reinterpret_cast<uint32_t*>(DAT_0093d592 * 0x4c + 4 + DAT_0093b274) & 0x2000) == 0 ||
                    FUN_00594960((int)DAT_0093d592) == 0)
                    DAT_0093d592 = DAT_0093d590;

                iVar4 = 0;
                if (DAT_007f39e4 != 0) {
                    local_2ac[0]    = DAT_007f1a1c; local_2ac[1]    = DAT_007f1960;
                    local_2ac[2]    = DAT_007f1a24; local_2ac[3]    = DAT_007f19a4;
                    local_2ac[4]    = DAT_007f1970; local_2ac[5]    = DAT_007f1a28;
                    local_2ac[6]    = DAT_007f196c; local_2ac[7]    = DAT_007f1964;
                    local_2ac[8]    = DAT_007f1a2c; local_2ac[9]    = DAT_007f195c;
                    local_2ac[10]   = DAT_007f1b2c; local_2ac[0xb]  = DAT_007f1a9c;
                    local_2ac[0xc]  = DAT_007f1b34; local_2ac[0xd]  = DAT_007f1a00;
                    local_2ac[0xe]  = DAT_007f19e4; local_2ac[0xf]  = DAT_007f19e8;
                    local_2ac[0x10] = DAT_007f1b1c; local_2ac[0x11] = DAT_007f1b3c;
                    local_2ac[0x12] = DAT_007f1b44; local_2ac[0x13] = DAT_007f1b40;
                    local_2ac[0x14] = DAT_007f1a98;
                    iVar4 = 0x15;
                }
                local_2ac[iVar4] = -1;
                iVar10 = DAT_0087a954;
                if (local_2ac[0] != -1) {
                    // !!!!!!!!!!! CALL J !!!!!!!!!!!
                    // add each char from freeplay controller list
                    short* psVar6 = local_2ac;
                    do {
                        iVar4 = FUN_004890e0(0, (int)*psVar6);
                        if (iVar4 != 0) iVar10++;
                        psVar6++;
                    } while (*psVar6 != -1);
                }
            } else {
                if (DAT_0093d592 == -1 ||
                    (*reinterpret_cast<uint32_t*>(DAT_0093d592 * 0x4c + 4 + DAT_0093b274) & 0x4000000) == 0 ||
                    FUN_00594960((int)DAT_0093d592) == 0) {
                    DAT_0093d592 = DAT_0093d590;
                    iVar10 = DAT_0087a954;
                }
            }
        }

        DAT_0087a954 = iVar10;

        if (PTR_DAT_007f17d8 != nullptr) {
            auto** ppuVar9 = &PTR_DAT_007f17dc;
            short* psVar6  = PTR_DAT_007f17d8;
            do {
                if (*psVar6 != -1 && DAT_0087b2c4 > 0) {
                    for (iVar4 = 0; iVar4 < DAT_0087b2c4; iVar4++) {
                        if (*reinterpret_cast<short*>(
                                reinterpret_cast<uintptr_t>(&DAT_0087a840) + iVar4) == *psVar6) {
                            auto* target = reinterpret_cast<short*>(*ppuVar9);
                            // !!!!!!!!!!! CALL K !!!!!!!!!!!
                            // add char from PTR_DAT_007f17dc linked list
                            if (target != nullptr && *target != -1)
                                FUN_004890e0(0, (int)*target);
                            break;
                        }
                    }
                }
                psVar6 = reinterpret_cast<short*>(ppuVar9[1]);
                ppuVar9 += 2;
            } while (psVar6 != nullptr);
        }
        // __security_check_cookie omitted — stack array replaced with heap.
    }
};

static void ApplyLimitPatches() {
    const uint16_t limit = static_cast<uint16_t>(NEW_CHAR_LIMIT);
    PatchU16(0x1F8F7, limit);
    PatchU16(0x1FAA5, limit);
    PatchU16(0x1FF1A, limit);
    PatchU16(0x3D8DC, limit);
    PatchU16(0x1C7DD, limit);
    PatchU16(0xCA2F0, limit);
}

static void InstallCodeCaves() {
    using namespace sunset::inst;
    nop(reinterpret_cast<void*>(0x00491639), 8);
    jmp(reinterpret_cast<void*>(0x00491639), reinterpret_cast<void*>(Cave1_Trampoline));
    nop(reinterpret_cast<void*>(0x004EF680), 6);
    jmp(reinterpret_cast<void*>(0x004EF680), reinterpret_cast<void*>(Cave2_Trampoline));
    nop(reinterpret_cast<void*>(0x0042B108), 5);
    jmp(reinterpret_cast<void*>(0x0042B108), reinterpret_cast<void*>(Cave3_Trampoline));
    nop(reinterpret_cast<void*>(0x0042B082), 5);
    jmp(reinterpret_cast<void*>(0x0042B082), reinterpret_cast<void*>(Cave4_Trampoline));
}

// shlock content incoming
#pragma comment(linker, "/EXPORT:Pentane_Main=_Pentane_Main@0")
extern "C" void __stdcall Pentane_Main() {
    Pentane_LogUTF8 = reinterpret_cast<void(*)(PentaneCStringView*)>(
        GetProcAddress(GetModuleHandleA("Pentane.dll"), "Pentane_LogUTF8"));

    g_buf_a        = static_cast<uint16_t*>(VirtualAlloc(nullptr, NEW_CHAR_LIMIT * 2,       MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
    g_buf_b        = static_cast<uint16_t*>(VirtualAlloc(nullptr, NEW_CHAR_LIMIT * 2,       MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
    g_buf_c        = static_cast<uint8_t*> (VirtualAlloc(nullptr, NEW_CHAR_LIMIT,           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
    g_type_flags   = static_cast<uint8_t*> (VirtualAlloc(nullptr, NEW_CHAR_LIMIT,           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
    g_cnt_flags    = static_cast<uint8_t*> (VirtualAlloc(nullptr, NEW_CHAR_LIMIT,           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));
    g_freeplay_buf = static_cast<short*>   (VirtualAlloc(nullptr, (NEW_CHAR_LIMIT + 1) * 2, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));

    if (!g_buf_a || !g_buf_b || !g_buf_c || !g_type_flags || !g_cnt_flags || !g_freeplay_buf) {
        logger::log("[Extended Character Limit] FATAL: buffer allocation failed.");
        return;
    }
    for (size_t i = 0; i <= NEW_CHAR_LIMIT; ++i) g_freeplay_buf[i] = -1;

    logger::log("[Extended Character Limit] New limit: " + std::to_string(NEW_CHAR_LIMIT));

    FreeplayCharacterSelection::install_at_ptr(0x00489150);

    ApplyLimitPatches();

    InstallCodeCaves();
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}