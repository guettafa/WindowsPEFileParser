#include "pch.h"
#include "peFile.h"

int main(int argc, char** argv)
{
	FILE* peFile;
	fopen_s(&peFile, argv[1], "rb");

	Parser pf(argv[1], peFile);

	pf.DisplayInfo();
	return 0;
}