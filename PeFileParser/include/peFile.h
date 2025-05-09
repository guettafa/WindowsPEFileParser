#ifndef PE_FILE_H
#define PE_FILE_H

#include "pch.h"

class PeFile
{
private:
	const char* m_PEFileName;
	FILE* m_PEFilePtr;
	
	IMAGE_DOS_HEADER m_DOSHeader;
	IMAGE_NT_HEADERS m_NTHeaders;

public:
	PeFile(const char* aPeFileName, FILE* aPeFilePtr)
		: m_PEFileName(aPeFileName), m_PEFilePtr(aPeFilePtr) 
	{}

	DWORD ParseDOSHeader();
};

#endif