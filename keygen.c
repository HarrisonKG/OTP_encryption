/* Kristen Harrison
CS 344, Program 4 -- OTP
*/

// Usage: ./keygen <keylength> [> keyfilename]


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>



/* generate key from 27 allowed chars 
and send output to stdout */
int main(int argc, char* argv[])
{
	srand(time(0));
	int size = 0;

	/* check that the requested size was entered */
	if (argv[1]){
		size = atoi(argv[1]);	
	}
	else {
		fprintf(stderr, "Invalid arguments: use format './keygen <key length>'\n");
		return 1;
	}

	/* these are the chars we can use */
	char validChars[28] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

	/* pick random chars from the string for the requested number of times */
	for (int i = 0; i < size; i++){
		printf("%c", validChars[rand() % 27]);
	}
	printf("\n");

	return 0;
}