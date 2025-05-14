#include "pch.h"
#include "peFile.h"

bool PeFile::ParseFile()
{
	if (ParseDOSHeader())       return 1;
	if (ParseNTHeaders())       return 1;
	if (ParseSectionHeaders())  return 1;
	if (ParseImportTable())		return 1;
	if (ParseRelocTable())		return 1;

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
	
	m_MagicNumber			= m_DOSHeader.e_magic;
	m_StartOfNTHeaderOffset = m_DOSHeader.e_lfanew;

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
	m_RelocDir    = m_DataDirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	
	return 0;
}

bool PeFile::ParseSectionHeaders()
{
	// To go to the start of Section Headers space
	DWORD OffSectionHeaders = m_DOSHeader.e_lfanew + sizeof(m_NTHeaders);
	
	for (int i = 0; i < m_NumberOfSectionHeaders; i++)
	{
		// Go on each section header
		// Set File ptr to the start of the first Section Header, 
		fseek(m_PEFilePtr, OffSectionHeaders + (i * IMAGE_SIZEOF_SECTION_HEADER), SEEK_SET);

		// Read each byte and store everything at the index pos of m_SectionHeaders array
		fread(&m_SectionHeaders[i], IMAGE_SIZEOF_SECTION_HEADER, 1, m_PEFilePtr);

		// Then go to the next Section Header and repeat everything
	}
	return 0;
}

bool PeFile::ParseImportTable()
{
	// eX : (23500 - 23000) + 0xf400 = 0xf900 = offset to the start of the import table
	DWORD OffImportedDLLs = (m_ImportDir.VirtualAddress - m_SectionHeaders[5].VirtualAddress) + m_SectionHeaders[5].PointerToRawData;
	
	size_t szIID = sizeof(IMAGE_IMPORT_DESCRIPTOR);

	// eX : 140 / 20 = 7 ( 7 imported dlls ) 
	// In reality 6 because of the null one at the end 
	
	m_NumImportedDLL	= (m_ImportDir.Size / szIID) - 1;
	m_ImportTable	    = new IMAGE_IMPORT_DESCRIPTOR[m_NumImportedDLL];
	m_SecondImportTable = new PeImport[m_NumImportedDLL];

	for (int i = 0; i < m_NumImportedDLL; i++)
	{
		DWORD OffDLL = OffImportedDLLs + (i * szIID);

		fseek(m_PEFilePtr, OffDLL, SEEK_SET);
		fread(&m_ImportTable[i], szIID, 1, m_PEFilePtr);

		DWORD OffDllName = (m_ImportTable[i].Name - m_ImportDir.VirtualAddress) + OffImportedDLLs;

		// Get dll name length
		int dllNameLen = 0;

		char c = (char)"";
		while (c != 0x00)
		{
			fseek(m_PEFilePtr, OffDllName + dllNameLen, SEEK_SET);
			fread(&c, 1, 1, m_PEFilePtr);
			
			dllNameLen++;
		}

		// Get dll name
		char* dllName = new char[dllNameLen];
		
		fseek(m_PEFilePtr, OffDllName, SEEK_SET);
		fread(dllName, dllNameLen, 1, m_PEFilePtr);

		// A more expressif Import table struct lol
		m_SecondImportTable[i] =
		{
			dllName,
			dllNameLen
		};
	}
	return 0;
}

bool PeFile::ParseRelocTable()
{
	uint16_t lastSizeOfBlock = 0;
	size_t	 szIBR			 = sizeof(IMAGE_BASE_RELOCATION);

	DWORD OffNextRelocBlock = m_SectionHeaders[9].PointerToRawData;

	while (OffNextRelocBlock != (OffNextRelocBlock + m_RelocDir.Size))
	{
		IMAGE_BASE_RELOCATION processedBlock{};

		fseek(m_PEFilePtr, OffNextRelocBlock, SEEK_SET);
		fread(&processedBlock, szIBR, 1, m_PEFilePtr);
		
		uint8_t totalEntries = (processedBlock.SizeOfBlock - szIBR) / SIZE_ENTRY;

		lastSizeOfBlock = processedBlock.SizeOfBlock;

		std::printf("Size of the block : %d - RVA : 0x%08x \n", lastSizeOfBlock, processedBlock.VirtualAddress);

		// Each entry is 2 bytes and each block start with the 8 byte struct IMAGE_BASE_RELOCATION
		std::printf("Number of entries : %d\n", totalEntries);
	
		for (int i = 0; i < totalEntries; i++)
		{
			DWORD OffEntry = (OffNextRelocBlock + szIBR) + (i * SIZE_ENTRY); // Each entry is 2 bytes
			std::printf("Offset of entry : 0x%08x\n", OffEntry);
		}
		OffNextRelocBlock += lastSizeOfBlock;
	}
	return 0;
}

void PeFile::DisplayInfo()
{
	DisplayDOSHeader();
	DisplayNTHeader();
	DisplaySectionHeaders();
	DisplayImportTable();
}

void PeFile::DisplayDOSHeader()
{
	std::printf("----- DOS HEADER -----\n");
	std::printf("Magic Number : 0x%08x\n", m_MagicNumber);
	std::printf("Offset Start of NT Header : 0x%08x\n\n", m_StartOfNTHeaderOffset);
}

void PeFile::DisplayNTHeader()
{
	std::printf("----- NT HEADER -----\n");

	std::printf("-----  -> FILE HEADER -----\n");
	std::printf("Arch : %s\n", m_Arch == IMAGE_FILE_MACHINE_AMD64 ? "AMD64" : "Other");
	std::printf("Timestamp : %d\n",		m_TimeStamp);
	std::printf("Number of sections : %d\n", m_NumberOfSectionHeaders);

	std::printf("-----  -> OPTIONAL HEADER -----\n");

	std::printf("64 or 32 ? : %s\n",			  m_Bit == IMG_BIT64 ? "64 bit" : "32 bit");
	std::printf("Size of Image : %d\n",			  m_SizeOfImage);
	//std::printf("RVA to code Section : 0x%08x\n", m_RVAToCode); // When loaded in memory only
	std::printf("Image Base : 0x%08x\n\n",		  m_ImageBase);
}

void PeFile::DisplaySectionHeaders()
{
	std::printf("----- SECTION HEADERS -----\n");

	for (int i = 0; i < m_NumberOfSectionHeaders; i++)
	{
		std::printf(
			"Name : %s - VA : 0x%08x - Pointer to Raw Data : 0x%08x\n", 
			m_SectionHeaders[i].Name, 
			m_SectionHeaders[i].VirtualAddress, 
			m_SectionHeaders[i].PointerToRawData
		);
	}
}

void PeFile::DisplayImportTable()
{
	std::printf("\n----- IMPORT TABLE -----\n");

	for (int i = 0; i < m_NumImportedDLL; i++)
	{
		std::printf(
			"Name : %s \n", 
			m_SecondImportTable[i].Name
		);
	}
}

