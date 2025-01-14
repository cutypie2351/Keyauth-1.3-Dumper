
#include "cutypie.hpp"
#include "cutypie_obfuscator.hpp"
#include <Windows.h>


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)

{
    Initialize();
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        keyauth_sigs->hook_sigs();
        keyauth_sigs->initialize_hooks();
        //keyauth_sigs->initialize_polyhook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}