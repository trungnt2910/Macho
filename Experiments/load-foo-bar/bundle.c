#include <stdio.h>
#include "bar.h"

int main(int argc, char **argv)
{
	printf("Hello World\n");
	return 1;
}

int foo()
{
	secret();
	printf("Hey, why are you here?\n");
	return 69;
}
