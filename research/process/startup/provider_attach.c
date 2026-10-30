#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifndef ACCEPT_ATTACH
#define ACCEPT_ATTACH 0
#endif
__declspec(dllexport) unsigned __cdecl independent_value(void) { return 7; }
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
 (void)module; (void)reserved;
 return reason == DLL_PROCESS_ATTACH ? ACCEPT_ATTACH : TRUE;
}
