/* Kristen Harrison
CS 344, Program 4 -- OTP
*/

// Encryption client 


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
	fprintf(stderr, "Error: otp_enc could not connect to otp_enc_d on port %i\n", portNumber); 
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

	// save plaintext and key files to strings
	char* plaintext = NULL;
	char* keytext = NULL;

	if (argv[1]){
		plaintext = readFileToString(argv[1], plaintext);
	}
	//printf("plaintext: %s\n", plaintext);

	if (argv[2]){
		keytext = readFileToString(argv[2], keytext);
	}
	//printf("key: %s\n", keytext);


	// check plaintext and key for invalid characters
	int pt_valid = checkValidChars(plaintext);	
	if (!pt_valid){
		fprintf(stderr, "Plaintext has invalid characters\n");
		exit(1);
	}

	int key_valid = checkValidChars(keytext);	
	if (!key_valid){
		fprintf(stderr, "Key has invalid characters\n");
		exit(1);
	}


	// key cannot be shorter than the plaintext
	if (strlen(keytext) < strlen(plaintext)){
		fprintf(stderr, "Key must be at least as long as plaintext\n");
		exit(1);
	}
	// truncate key to the size of the plaintext, for efficiency
	else if (strlen(keytext) > strlen(plaintext)){
		keytext[strlen(plaintext)] = '\0';
	}
	//printf("key length: %lu\n", strlen(keytext));
	//printf("plaintext length: %lu\n", strlen(plaintext));


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
	int bufferSize = strlen(plaintext) + strlen(keytext) + 5;
	char buffer[bufferSize];
	memset(buffer, '\0', bufferSize); // Clear out the buffer array
	sprintf(buffer, "e.%s&%s@@", plaintext, keytext);
	//printf("string to send: %s\n", buffer);


	// send in loop to server
	int total = 0;
	int bytesLeft = strlen(buffer);

	while(bytesLeft > 0){
		charsWritten = send(socketFD, buffer + total, 1000, 0);
		//printf("CLIENT: chars written: %i", charsWritten);
		if (charsWritten < 0){
			perror("CLIENT: ERROR writing to socket");
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
			perror("CLIENT: ERROR reading from socket");
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
	free(plaintext);
	close(socketFD); 
	free(keytext);
	return 0;
}
