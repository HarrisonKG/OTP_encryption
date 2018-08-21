/* Kristen Harrison
CS 344, Program 4 -- OTP
*/

// Encryption server 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>




// Error function used for reporting issues
void error(const char *msg) { 
	perror(msg); 
	exit(1); 
}



// valid chars (capitals plus space) translates into A=0, B=1 ... Z=25, space=26
int intCode(char c){
	int i = c - 65; 
	if (i < 0){
		i = 26;
	}
	return i;
}



// int input between 0 and 26 mapped back to ascii chars
char charCode(int i){
	char c = 'A' + i;
	if (c > 90){
		c = ' ';
	}
	return c;
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
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
	socklen_t sizeOfClientInfo;
	struct sockaddr_in serverAddress, clientAddress;
	
	// Check usage & args
	if (argc < 2) { 
		fprintf(stderr,"USAGE: %s port\n", argv[0]); 
		exit(1); 
	} 

	// Get the port number, convert to an integer from a string
	portNumber = atoi(argv[1]); 
	// check port number is in valid range
	if (portNumber < 1024 || portNumber > 65535){
		fprintf(stderr, "Use ports from 1024 to 65535\n");
		exit(1);
	}


	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); //	Clear out the address struct
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process
	
	// Create the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); 
	if (listenSocketFD < 0) 
		error("SERVER: ERROR opening socket");
	
	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, 
	sizeof(serverAddress)) < 0) // Connect socket to port
		error("SERVER: ERROR on binding");
	
	// Flip the socket on - it can now receive up to 5 connections
	listen(listenSocketFD, 5); 
	

	// server parent process lives forever, listening for connections
	while (1){
		// Get the size of the address for the client that will connect
		sizeOfClientInfo = sizeof(clientAddress); 

		// Accept a connection, blocking if one is not available until one connects
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr 
		*)&clientAddress, &sizeOfClientInfo); 
		
		if (establishedConnectionFD < 0) 
			error("SERVER: ERROR on accept");

		
		// fork process
		pid_t spawnPID = -5;
		spawnPID = fork();

		if (spawnPID == -1){
			error("Fork failed");
		}
		// handle new connection with child
		else if (spawnPID == 0){

			// buffers for receiving string
			char completeMsg[200000];
			char buffer[1000];
			memset(completeMsg, '\0', 200000);

			// loop until we find the null terminator
			while (strstr(completeMsg, "@@") == NULL){
				memset(buffer, '\0', 1000);
				// read message in chunks
				charsRead = recv(establishedConnectionFD, buffer, 999, 0);

				// check for errors
				if (charsRead < 0) {
					error("SERVER: ERROR reading from socket");
				} else if (charsRead == 0){
					fprintf(stderr, "SERVER: No characters read\n"); 
					exit(1);
				}
				
				// add new chunk to our saved string
				strcat(completeMsg, buffer);
				//printf("chars read: %i\nMessage so far: %s\n", charsRead, completeMsg);
			}

			// terminate message string
			int terminalIndex = strstr(completeMsg, "@@") - completeMsg + 2;
			completeMsg[terminalIndex] = '\0';
			//printf("SERVER: complete string: \"%s\"\n", completeMsg);

			// verify that the connection is with otp_enc
			if (completeMsg[0] != 'e'){
				fprintf(stderr, "SERVER: Connection is not with otp_enc\n");
				exit(1);
			}

			// store plaintext and key
			char plaintext[100000];
			char keytext[100000];
			memset(plaintext, '\0', 100000);
			memset(keytext, '\0', 100000);
			
			// use buffer copy to check that the chars are valid
			char buffer_copy[strlen(completeMsg)];
			memset(buffer_copy, '\0', strlen(completeMsg));
			strcpy(buffer_copy, completeMsg);
			//printf("buffer copy: %s", buffer_copy); fflush(stdout);


			// blank out first two chars, @@ at end and first & 
			buffer_copy[0] = ' ';
			buffer_copy[1] = ' ';
			buffer_copy[strlen(completeMsg)-1] = ' ';
			buffer_copy[strlen(completeMsg)-2] = ' ';
			char* divider = strstr(buffer_copy, "&");
			*divider = ' ';

			// check if the rest is valid chars
			int input_valid = checkValidChars(buffer_copy);	
			if (!input_valid){
				fprintf(stderr, "SERVER: The text sent has invalid characters\n");
				exit(1);
			}
			else {
				// mark end of plaintext string
				char* pt_end = strstr(completeMsg, "&");
				// pt starts at buffer[2], after "e."
				strncpy(plaintext, completeMsg + 2, pt_end - completeMsg - 2);
				//printf("pt: %s\nlength: %lu\n", plaintext, strlen(plaintext));

				// key starts after the '&' symbol and ends at the '@@'
				char* key_start = pt_end + 1;
				char* key_end = strstr(completeMsg, "@@");
				strncpy(keytext, key_start, key_end - key_start);
				//printf("key: %s\nlength: %lu\n", keytext, strlen(keytext));

				// check that key length >= ciphertext length
				if (strlen(keytext) < strlen(plaintext)){
					fprintf(stderr, "SERVER: Key must be at least as long as plaintext\n");
					exit(1);
				}	


				// convert to ciphertext, leaving room for suffix @@
				char ciphertext[strlen(plaintext)+2];
				memset(ciphertext, '\0', strlen(plaintext)+2);

				for(int i = 0; i < strlen(plaintext); i++){
					//printf("%c ", plaintext[i]);
					//printf("%i ", intCode(plaintext[i]));
					//printf("%c ", keytext[i]);
					//printf("%i ", intCode(keytext[i]));
					int sum = (intCode(plaintext[i]) + intCode(keytext[i])) % 27;
					//printf("sum: %i  ", sum);
					ciphertext[i] = charCode(sum);
					//printf("cipherchar: %c\n", ciphertext[i]);
				}
				strcat(ciphertext, "@@");
				//printf("\nciphertext: %s\n", ciphertext);
				
				int total = 0;
				int bytesLeft = strlen(ciphertext);
				int charsWritten;
				//printf("ciphertext: %s\n cipher length: %lu\n", ciphertext, strlen(ciphertext)); fflush(stdout);

				while(bytesLeft > 0){
					charsWritten = send(establishedConnectionFD, ciphertext + total, 999, 0);
					//printf("SERVER: chars written: %i", charsWritten);
					if (charsWritten < 0){
						error("SERVER: ERROR writing to socket");
					} else if (charsWritten == 0){
						fprintf(stderr, "SERVER: No characters written\n"); 
						exit(1);
					}
					total += charsWritten;
					bytesLeft -= charsWritten;
					//printf("total: %i\nbytes left: %i\n", total, bytesLeft);
				}
			}
			// terminate child process
			exit(0);
		}// end child block

		// reap zombies (check if any child is done, don't block)
		waitpid(0, NULL, WNOHANG);
		// Close the existing socket which is connected to the client
		close(establishedConnectionFD); 
		// parent continues listening for new connections
	} //endwhile

	// Close the parent process's listening socket
	close(listenSocketFD);
	return 0;
}
