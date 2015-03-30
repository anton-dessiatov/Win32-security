#ifndef __HS_WIN32SECURITY_H
#define __HS_WIN32SECURITY_H

#include <windows.h>

void LocalFreeFinaliser(void* p);
void CloseHandleFinaliser(HANDLE h);

#endif // __HS_WIN32SECURITY_H
