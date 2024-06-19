#include "Plugin_SDK.h"
#include "blake3.h"

const GUID pluginGuid = GUID{
    0x0fa461aa, 0xf17d, 0x4819, { 0xab, 0xec, 0xf9, 0x53, 0x42, 0x82, 0x15, 0xce }
};

const char16_t* hashName = (const char16_t*)L"BLAKE3";

const GUID hashGuid = GUID{
    0x896474b1, 0x162d, 0x42db, { 0x2a, 0x91, 0x04, 0xad, 0x48, 0x76, 0x77, 0x68 }
};

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpReserved) {
    return TRUE;
}

BOOL HSPCALL HSP_Initialize(CPHSP_InitInfo cpInitInfo, PHSP_PluginBasicInfo pPluginBasicInfo) {
    pPluginBasicInfo->eHSPFuncFlags = HSPFuncFlags_Hash;
    pPluginBasicInfo->pGuid = &pluginGuid;
    pPluginBasicInfo->pluginInterfaceVer = HSP_INTERFACE_VER;
    pPluginBasicInfo->pluginSDKVer = HSP_SDK_VER;
    return TRUE;
}

LRESULT HSPCALL HSP_PluginFunc(HSPPFMsg uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == HSPPFMsg_Hash_GetSupportAlgCount) return 1;

    auto AlgID = (uint32_t)lParam;
    if (AlgID == 0) {
        if (uMsg == HSPPFMsg_Hash_GetAlgInfo) {
            auto pAlgInfo = (PHSP_AlgInfo)wParam;
            pAlgInfo->BlockSizeOctets = 0;
            pAlgInfo->DigestSize = 32;
            pAlgInfo->szAlgName = hashName;
            return TRUE;
        }
        if (uMsg == HSPPFMsg_Hash_GetAlgInfoEx) {
            auto pAlgInfoEx = (PHSP_AlgInfoEx)wParam;
            pAlgInfoEx->eHSPAlgFlags = HSPAlgFlags_None;
            pAlgInfoEx->pGuid = &hashGuid;
            pAlgInfoEx->szAlgFileName = hashName;
            return TRUE;
        }
        if (uMsg == HSPPFMsg_Hash_GetAlgFunctions) {
            auto pAlgFunctions = (PHSP_AlgFunctions)wParam;
            pAlgFunctions->fpHSP_HashInitialize = [](uint32_t AlgID) -> void* {
                auto state = new blake3_hasher();
                blake3_hasher_init(state);
                return state;
            };
            pAlgFunctions->fpHSP_HashUpdate = [](void* state, const uint8_t* data, rsize_t dataOctets) {
                blake3_hasher_update((blake3_hasher*)state, data, dataOctets);
            };
            pAlgFunctions->fpHSP_HashGetHex = [](void* state, uint8_t* digest, rsize_t getOctets) {
                blake3_hasher_finalize((blake3_hasher*)state, digest, getOctets);
            };
            pAlgFunctions->fpHSP_HashReset = [](void* state) {
                blake3_hasher_init((blake3_hasher*)state);
            };
            pAlgFunctions->fpHSP_HashFinalize = [](void* state) {
                delete (blake3_hasher*)state;
            };
            pAlgFunctions->fpHSP_HashClone = [](void* state) -> void* {
                auto clone = new blake3_hasher();
                *clone = *(blake3_hasher*)state;
                return clone;
            };
            return TRUE;
        }
    }
    return FALSE;
}
