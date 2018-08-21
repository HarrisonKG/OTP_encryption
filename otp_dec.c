/* Kristen Harrison
CS 344, Program 4 -- OTP
*/

// Decryption client 


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>



void pConnError(int portNumber){
	fprintf(stderr, "Error: otp_dec could not connect to otp_dec_d on port %i\n", portNumber); 
}



// reads variable-length files to string
char* readFileToString(char* filepath, char* text)
{
	size_t size = 0;
	FILE* fp = fopen(filepath, "r");

	if(fp){
		// check how long the file is 
		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		// go back to the beginning 
		rewind(fp);
		// allocate memory
		text = malloc(size * sizeof(text));
		// read file into string, null terminate
		fread(text, size, 1, fp);
		text[size-1] = '\0';

		//printf("file contents: %s\n%lu\n", text, size);
		return text;
	}
	else {
		perror("Unable to open file");
		exit(1);
		return NULL;
	}

	fclose(fp);
}



int checkValidChars(char* text)
{
	int valid = 1;
	// check each char in the input string 
	for (int i = 0; i < strlen(text); i++){
		// valid chars are ascii 32 or 65 through 90
		if ((text[i] < 65 || text[i] > 90) && text[i] != 32){
			valid = 0;
		}
	}
	//printf("valid: %i\n", valid);
	return valid;
}



int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;

	// Check usage & args
	if (argc < 4) { 
		fprintf(stderr,"USAGE: %s plaintextfile keyfile port\n", argv[0]); 
		exit(1); 
	} 
	
	// Get the port number, convert to an integer from a string
	portNumber = atoi(argv[3]); 
	// check port number is in valid range
	if (portNumber < 1024 || portNumber > 65535){
		fprintf(stderr, "Use ports from 1024 to 65535\n");
		exit(1);
	}


	// save ciphertext and key files to strings
	char* ciphertext = NULL;
	char* keytext = NULL;

	if (argv[1]){
		ciphertext = readFileToString(argv[1], ciphertext);
	}
	//printf("ciphertext: %s\n", ciphertext);

	if (argv[2]){
		keytext = readFileToString(argv[2], keytext);
	}
	//printf("key: %s\n", keytext);


	// check ciphertext and key for invalid characters
	int ct_valid = checkValidChars(ciphertext);	
	if (!ct_valid){
		fprintf(stderr, "Ciphertext has invalid characters\n");
		exit(1);
	}

	int key_valid = checkValidChars(keytext);	
	if (!key_valid){
		fprintf(stderr, "Key has invalid characters\n");
		exit(1);
	}


	// key cannot be shorter than the ciphertext
	if (strlen(keytext) < strlen(ciphertext)){
		fprintf(stderr, "Key must be at least as long as ciphertext\n");
		exit(1);
	}
	// truncate key to the size of the ciphertext, for efficiency
	else if (strlen(keytext) > strlen(ciphertext)){
		keytext[strlen(ciphertext)] = '\0';
	}
	//printf("key length: %lu\n", strlen(keytext));
	//printf("ciphertext length: %lu\n", strlen(ciphertext));


	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address

	if (serverHostInfo == NULL) { 
		fprintf(stderr, "CLIENT: ERROR, could not resolve host name\n"); 
		exit(2); 
	}

	// Copy in the address
	memcpy((char*)&serverAddress.sin_addr.s_addr, 
		(char*)serverHostInfo->h_addr, serverHostInfo->h_length); 


	// Create the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); 
	if (socketFD < 0){
		perror("CLIENT: ERROR opening socket");
		exit(2);
	}

	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, 
	sizeof(serverAddress)) < 0){ // Connect socket to address
		perror("CLIENT: ERROR connecting");
		pConnError(portNumber); exit(2);
	}


	// Construct buffer string to send
	int bufferSize = strlen(ciphertext) + strlen(keytext) + 5;
	char buffer[bufferSize];
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
	sprintf(buffer, "d.%s&%s@@", ciphertext, keytext);
	//printf("%s\n", buffer);


	// send in loop to server
	int total = 0;
	int bytesLeft = strlen(buffer);

	while(bytesLeft > 0){
		charsWritten = send(socketFD, buffer + total, 1000, 0);
		//printf("CLIENT: chars written: %i\n", charsWritten); fflush(stdout);
		if (charsWritten < 0){
			perror("CLIENT: Error writing to socket");
			pConnError(portNumber); exit(2);
		} else if (charsWritten == 0){
			fprintf(stderr, "CLIENT: No characters written\n");
			pConnError(portNumber); exit(2);
		}
		total += charsWritten;
		bytesLeft -= charsWritten;
	}


	// Get ciphertext back from server
	char completeMsg[100000];
	memset(completeMsg, '\0', 100000);
	char recvBuffer[1000];
	memset(recvBuffer, '\0', 1000);

	while (strstr(completeMsg, "@@") == NULL){
		memset(recvBuffer, '\0', 1000);
		// read message in chunks
		charsRead = recv(socketFD, recvBuffer, 999, 0); 
		if (charsRead < 0){
			perror("CLIENT: Error reading from socket");
			pConnError(portNumber); exit(2);
		} else if (charsRead == 0){
			fprintf(stderr, "CLIENT: No characters read\n");
			pConnError(portNumber); exit(2);
		}
		strcat(completeMsg, recvBuffer);
		//printf("chars read: %i\nMessage so far: %s\n", charsRead, completeMsg);
	}

	// terminate message string and remove @@
	int terminalPtr = strstr(completeMsg, "@@") - completeMsg;
	completeMsg[terminalPtr] = '\0';

	// output ciphertext to stdout
	printf("%s\n", completeMsg);
	
	
	// Close the socket
	close(socketFD); 
	free(ciphertext);
	free(keytext);
	return 0;
}
