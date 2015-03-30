#include "Win32Security.h"

void LocalFreeFinaliser(void* p) {
  LocalFree(p);
}

void CloseHandleFinaliser(HANDLE h) {
  CloseHandle(h);
}
