#include "pch.h"
#include "peFile.h"

int main(int argc, char** argv)
{
	FILE* peFile;
	fopen_s(&peFile, argv[1], "rb");
	
	PeFile pf(argv[1], peFile);

	DWORD magicNumber = pf.ParseDOSHeader();
	std::printf("Magic Number : 0x%08x\n", magicNumber);

	if (magicNumber == 0x5A4D)
	{
		std::printf("This file is a PE File\n");
	}

	return 0;
}