#include "pch.h"
#include "peFile.h"

bool PeFile::ParseFile()
{
	if (ParseDOSHeader())         return 1;
	if (ParseNTHeaders())         return 1;
	if (ParseSectionHeaders())    return 1;
	if (ParseaImportDirTable())   return 1;

	return 0;
}

bool PeFile::ParseDOSHeader()
{
	std::printf("PE FileName : %s\n", m_PEFileName);
	
	fseek(m_PEFilePtr, 0, SEEK_SET);							   // Set File ptr at the start of the PE File
	fread(&m_DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, m_PEFilePtr); // Read each byte until the end of the DOS Header
	
	if (m_DOSHeader.e_magic != EXECUTABLE_MARK)
	{
		std::printf("This file is not a PE File\n");
		return 1;
	}
	return 0;
}

bool PeFile::ParseNTHeaders()
{
	fseek(m_PEFilePtr,  m_DOSHeader.e_lfanew, SEEK_SET);
	fread(&m_NTHeaders, sizeof(IMAGE_NT_HEADERS), 1, m_PEFilePtr);

	// File Header
	m_Arch					 = m_NTHeaders.FileHeader.Machine;
	m_TimeStamp				 = m_NTHeaders.FileHeader.TimeDateStamp;
	m_NumberOfSectionHeaders = m_NTHeaders.FileHeader.NumberOfSections;
	m_SectionHeaders		 = new IMAGE_SECTION_HEADER[m_NumberOfSectionHeaders];

	// Optional Header
	m_Bit		  = m_NTHeaders.OptionalHeader.Magic;
	m_ImageBase	  = m_NTHeaders.OptionalHeader.ImageBase;
	m_SizeOfImage = m_NTHeaders.OptionalHeader.SizeOfImage;

	// Optional Header - Data dirs
	m_DataDirs	  = m_NTHeaders.OptionalHeader.DataDirectory;
	m_ImportDir	  = m_DataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
	m_ExportDir	  = m_DataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
	
	//std::printf("Arch : 0x%08x - Bit : 0x%08x\n", m_Arch, m_Bit);
	//std::printf("VA of Import Directory Table : 0x%08x / Size : %d\n", m_ImportDir.VirtualAddress, m_ImportDir.Size);
	//std::printf("Image Base Address : 0x%08x - Size of Image Base : %d\n", m_ImageBase, m_SizeOfImage);
	 
	return 0;
}

bool PeFile::ParseSectionHeaders()
{
	// To go to the start of Section Headers space
	DWORD OffSectionHeaders = m_DOSHeader.e_lfanew + sizeof(m_NTHeaders);
	
	//std::printf("Offset Section Header : 0x%08x\n", OffSectionHeaders);

	for (int i = 0; i < m_NumberOfSectionHeaders; i++)
	{
		// Go on each section header
		// Set File ptr to the start of the first Section Header, 
		fseek(m_PEFilePtr, OffSectionHeaders + (i * IMAGE_SIZEOF_SECTION_HEADER), SEEK_SET);

		// Read each byte and store everything at the index pos of m_SectionHeaders array
		fread(&m_SectionHeaders[i], IMAGE_SIZEOF_SECTION_HEADER, 1, m_PEFilePtr);

		// Then go to the next Section Header and repeat everything
	}
	//std::printf("Name : %s - Section Header VA : 0x%08x - Ptr to Raw Data : 0x%08x\n", m_SectionHeaders[5].Name, m_SectionHeaders[5].VirtualAddress, m_SectionHeaders[5].PointerToRawData);
	return 0;
}

bool PeFile::ParseaImportDirTable()
{
	// eX : (23500 - 23000) + 0xf400 = 0xf900 = offset to the start of the import table
	DWORD OffImportedDLLs = (m_ImportDir.VirtualAddress - m_SectionHeaders[5].VirtualAddress) + m_SectionHeaders[5].PointerToRawData;
	
	size_t szIID = sizeof(IMAGE_IMPORT_DESCRIPTOR);

	// eX : 140 / 20 = 7 ( 7 imported dlls ) 
	int numImportedDLL = (m_ImportDir.Size / szIID) - 1; // because last one is null

	m_ImportTable = new IMAGE_IMPORT_DESCRIPTOR[numImportedDLL];
	m_SecondImportTable = new PeImport[numImportedDLL];

	for (int i = 0; i < numImportedDLL; i++)
	{
		DWORD OffDLL = OffImportedDLLs + (i * szIID);

		fseek(m_PEFilePtr, OffDLL, SEEK_SET);
		fread(&m_ImportTable[i], szIID, 1, m_PEFilePtr);
		fread(&m_ImportTable[i], szIID, 1, m_PEFilePtr);

		DWORD OffName = (m_ImportTable[i].Name - m_ImportDir.VirtualAddress) + OffImportedDLLs;

		// Get dll name length
		int nameLengthDLL = 0;

		char c = (char)"";
		while (c != 0x00)
		{
			fseek(m_PEFilePtr, OffName + nameLengthDLL, SEEK_SET);
			fread(&c, 1, 1, m_PEFilePtr);
			
			nameLengthDLL++;
		}

		// Get dll name
		char* nameDLL = new char[nameLengthDLL];
		
		fseek(m_PEFilePtr, OffName, SEEK_SET);
		fread(nameDLL, nameLengthDLL, 1, m_PEFilePtr);

		// A more expressif Import table struct lol
		m_SecondImportTable[i] =
		{
			nameDLL,
			nameLengthDLL
		};
	}
	return 0;
}

