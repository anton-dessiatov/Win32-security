#ifndef __HS_WIN32SECURITY_H
#define __HS_WIN32SECURITY_H

#include <windows.h>

void HS_Win32Security_LocalFreeFinaliser(void* p);
void HS_Win32Security_CloseHandleFinaliser(HANDLE h);

#endif // __HS_WIN32SECURITY_H
