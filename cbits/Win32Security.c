#include "Win32Security.h"

#include <windows.h>

void LocalFreeFinaliser(void* p) {
  LocalFree(p);
}
