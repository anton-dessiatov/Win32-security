#include "Win32Security.h"

void HS_Win32Security_LocalFreeFinaliser(void* p) {
  LocalFree(p);
}

void HS_Win32Security_CloseHandleFinaliser(HANDLE h) {
  CloseHandle(h);
}
