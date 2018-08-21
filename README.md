Kristen Harrison  
344 -- Operating Systems  
  
I used socket-based inter-process communication to encrypt and decrypt information using a one-time-pad system. Two programs behaved as servers and two as clients, and one was a standalone key generator.   
  
First, compile everything using the bash script ./compileall  
  
Then start the encryption and decryption servers in the background with the port number as an argument, like:   
./otp_dec_d 50000 &  
./otp_enc_d 50001 &  
  
Create a key with the desired size as the argument:  
./keygen 700 > keyfile700  
  
Then you can encrypt text using the encryption client:  
./otp_enc plaintext1 keyfile700 50001 > ciphertext1  
    
And you can decrypt using the decryption client and the same keyfile:  
./otp_dec ciphertext1 keyfile700 50000 > decodedtext1
