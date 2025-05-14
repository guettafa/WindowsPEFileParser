#include "peFile.h"

int main(int argc, char** argv)
{
	FILE* peFile;
	fopen_s(&peFile, argv[1], "rb");

	Parser parser(argv[1], peFile);

	parser.DisplayInfo();
	return 0;
}