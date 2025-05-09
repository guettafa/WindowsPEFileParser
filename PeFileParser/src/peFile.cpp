#include "pch.h"
#include "peFile.h"

 DWORD PeFile::ParseDOSHeader()
{
	std::printf("PE FileName : %s\n", m_PEFileName);
	
	// set File ptr at the start of the PE File
	fseek(m_PEFilePtr, 0, SEEK_SET);
	// Read each byte until the end of the DOS Header
	fread(&m_DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, m_PEFilePtr); 

	return m_DOSHeader.e_magic;
}
