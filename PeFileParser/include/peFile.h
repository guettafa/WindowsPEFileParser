#ifndef PE_FILE_H
#define PE_FILE_H

#include "pch.h"
#include "constants.h"

class PeFile
{
private:
	const char* m_PEFileName;
	FILE*		m_PEFilePtr;
	
	IMAGE_DOS_HEADER m_DOSHeader;
	IMAGE_NT_HEADERS m_NTHeaders;
	
	// DOS Header
	
	DWORD m_MagicNumber;

	// NT Headers -- File Header

	WORD  m_Arch;					// CPU Arch
	DWORD m_TimeStamp;				// UNIX TimeStamp
	DWORD m_NumberOfSectionHeaders; // Number of Section Headers
	DWORD m_Characteristics;		// Executable, DLL, ...

	// NT Headers -- Optional Header
	
	WORD  m_Bit;					// x86 or x64
	DWORD m_RVAToCode;				// Relative Address of start of the code section when file loaded
	ULONGLONG m_ImageBase;			// Desired Image Base Address
	DWORD m_SizeOfImage;		    // Size of image including all Headers

	IMAGE_DATA_DIRECTORY m_Imports; // Import Table
	IMAGE_DATA_DIRECTORY m_Exports; // Export Table

	// Section Headers
	
	IMAGE_SECTION_HEADER* m_SectionHeaders; // Array of with all Section Headers

public:
	bool ParseDOSHeader();
	bool ParseNTHeaders();
	bool ParseSectionHeaders();

	inline PeFile(const char* aPeFileName, FILE* aPeFilePtr)
		: m_PEFileName(aPeFileName), m_PEFilePtr(aPeFilePtr) 
	{
		if (ParseDOSHeader())      return;
		if (ParseNTHeaders())      return;
		if (ParseSectionHeaders()) return;
	}

	inline ~PeFile()
	{
		delete[] m_SectionHeaders;
	}
};

#endif