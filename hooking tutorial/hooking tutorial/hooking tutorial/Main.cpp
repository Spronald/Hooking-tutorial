#include <Windows.h>

bool Hook(void* toHook, void* ourFunct, int len) {
	if (len < 5) {
		return false;
	}

	DWORD curProtection;
	VirtualProtect(toHook, len, PAGE_EXECUTE_READWRITE, &curProtection);

	memset(toHook, 0x90, len);//saying it wants all the bytes cleared

	DWORD relativeAddress = ((DWORD)ourFunct - (DWORD)toHook) - 5;//offset from our jmp address

	*(BYTE*)toHook = 0xE9; //first op code in jmp instruction
	*(DWORD*)((DWORD)toHook + 1) = relativeAddress;

	DWORD temp;
	VirtualProtect(toHook, len, curProtection, &temp);

	return true;
}


DWORD jmpBackAddy;
void _declspec(naked) ourFunct() {//No epiloge or No Prologe 
	__asm {//no other assembly but this when we compile
		add ecx, ecx
		mov edx, [ebp-8]
		jmp [jmpBackAddy]
	}
}

DWORD WINAPI MainThread(LPVOID param) {
	DWORD hookAddress = 0x332768;
	int hookLength = 6;
	jmpBackAddy = hookAddress + hookLength; // Telling the what the jmpBackAddy = 

	Hook((void*)hookAddress, ourFunct, hookLength);

	while (true) {
		if (GetAsyncKeyState(VK_ESCAPE)) break;
		Sleep(200);
	}

	FreeLibraryAndExitThread((HMODULE)param, 0);

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, MainThread, hModule, 0, 0);
		break;
	}

	return TRUE;
}