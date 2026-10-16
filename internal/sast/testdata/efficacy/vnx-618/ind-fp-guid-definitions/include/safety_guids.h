#ifndef SAFETY_GUIDS_H
#define SAFETY_GUIDS_H

#include <objbase.h>

#ifndef INTERFACESAFE_FOR_UNTRUSTED_CALLER
#define INTERFACESAFE_FOR_UNTRUSTED_CALLER 0x00000001
#define INTERFACESAFE_FOR_UNTRUSTED_DATA   0x00000002
#endif

DEFINE_GUID(CATID_SafeForScripting,    0x7dd95801, 0x9882, 0x11cf, 0x9f, 0xa9, 0x00, 0xaa, 0x00, 0x6c, 0x42, 0xc4);
DEFINE_GUID(CATID_SafeForInitializing, 0x7dd95802, 0x9882, 0x11cf, 0x9f, 0xa9, 0x00, 0xaa, 0x00, 0x6c, 0x42, 0xc4);

extern const CATID CATID_SafeForScripting;
extern const CATID CATID_SafeForInitializing;

#endif
