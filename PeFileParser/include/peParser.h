#ifndef PE_PARSER_H
#define PE_PARSER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include "constants.h"

struct PeImport
{
	char* Name;
	int   Length;
};

class Parser
{
private:
	bool ParseDOSHeader();
	bool ParseNTHeaders();
	bool ParseSectionHeaders();
	bool ParseImportTable();
	bool ParseRelocTable();

	void DisplayDOSHeader();
	void DisplayNTHeader();
	void DisplaySectionHeaders();
	void DisplayImportTable();
	void DisplayRelocTable();

	const char* m_PEFileName;
	FILE*		m_PEFilePtr;
	
	IMAGE_DOS_HEADER m_DOSHeader;
	IMAGE_NT_HEADERS m_NTHeaders;
	
	// DOS Header
	
	DWORD m_MagicNumber;
	DWORD m_StartOfNTHeaderOffset;

	// NT Headers -- File Header

	WORD  m_Arch;							      // CPU Arch
	DWORD m_TimeStamp;						      // UNIX TimeStamp
	DWORD m_NumberOfSectionHeaders;			      // Number of Section Headers
	DWORD m_Characteristics;				      // Executable, DLL, ...
											      
	// NT Headers -- Optional Header		      
											      
	WORD  m_Bit;							      // x86 or x64
	DWORD m_RVAToCode;						      // Relative Address of start of the code section when file loaded
	DWORD m_ImageBase;						      // Desired Image Base Address
	DWORD m_SizeOfImage;					      // Size of image including all Headers
	
	// NT Headers -- Optional Header - Data Dirs

	IMAGE_DATA_DIRECTORY*    m_DataDirs;		  // Array of Data Directory Entries

	IMAGE_DATA_DIRECTORY     m_RelocDir;		  // Relocation Table
	IMAGE_BASE_RELOCATION*	 m_RelocTable;		  // All relocations blocks
	int						 m_TotalRelocBlock;
	
	IMAGE_DATA_DIRECTORY     m_ImportDir;		  // Import Table 
	IMAGE_IMPORT_DESCRIPTOR* m_ImportTable;		  // All dlls imported
	PeImport*				 m_SecondImportTable; // A second "import table"
	int						 m_NumImportedDLL;

	// Section Headers
	
	IMAGE_SECTION_HEADER* m_SectionHeaders; // Array with all Section Headers

public:
	bool ParseFile();
	void DisplayInfo();

	inline Parser(const char* aPeFileName, FILE* aPeFilePtr)
		: m_PEFileName(aPeFileName), m_PEFilePtr(aPeFilePtr) 
	{
		if (ParseFile()) return;
	}

	inline ~Parser()
	{
		free(m_RelocTable); // using malloc for it

		delete[] m_SecondImportTable;
		delete[] m_ImportTable;
		delete[] m_SectionHeaders;
	}
};

#endif
