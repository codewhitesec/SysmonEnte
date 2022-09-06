#ifndef MISC_H
#define MISC_H

#include "windows.h"

PWSTR toLowerW(PWSTR);
PSTR toLowerA(PSTR);
unsigned long djb2(PCSTR);
unsigned long djb2_unicode(PCWSTR);

#endif