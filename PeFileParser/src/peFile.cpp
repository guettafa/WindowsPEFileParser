#include "pch.h"
#include "peFile.h"

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

	m_MagicNumber = m_DOSHeader.e_magic;

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
	m_Bit     = m_NTHeaders.OptionalHeader.Magic;
	m_Exports = m_NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	m_Imports = m_NTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	
	std::printf("Arch : 0x%08x - Bit : 0x%08x\n", m_Arch, m_Bit);
	std::printf("VA of Import Directory Table : 0x%08x / Size : %d\n", m_Imports.VirtualAddress, m_Imports.Size);
	 
	return 0;
}

bool PeFile::ParseSectionHeaders()
{
	// To go to the start of Section Headers space
	int OffSectionHeaders = m_DOSHeader.e_lfanew + sizeof(m_NTHeaders);
	
	for (int i = 0; i < m_NumberOfSectionHeaders; i++)
	{
		// Go on each section header
		// Set File ptr to the start of the first Section Header, 
		fseek(m_PEFilePtr, OffSectionHeaders + (i * IMAGE_SIZEOF_SECTION_HEADER), SEEK_SET);

		// Read each byte and store everything at the index pos of m_SectionHeaders array
		fread(&m_SectionHeaders[i], IMAGE_SIZEOF_SECTION_HEADER, 1, m_PEFilePtr);

		// Then go to the next Section Header and repeat everything
	}
	std::printf("Import Directory Table VA : 0x%08x\n", m_SectionHeaders[5].VirtualAddress);
	return 0;
}

