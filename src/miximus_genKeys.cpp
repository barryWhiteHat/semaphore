#include "miximus.hpp"

#include <stdio.h>
#include <stdlib.h>

int main( int argc, char **argv )
{
	if( argc < 4 ) {
		fprintf(stderr, "Usage: %s <tree-depth> <pk-output.raw> <vk-output.json>\n", argv[0]);
		return 1;
	}

	int tree_depth = atoi(argv[1]);
	if( tree_depth < 1 ) {
		fprintf(stderr, "Error: invalid tree depth\n");
		return 2;
	}

	genKeys(tree_depth, argv[2], argv[3]);

	return 0;
}
