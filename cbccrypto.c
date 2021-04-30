// Cody Clark 30010560
/*
	Because decryption in CBC mode only relies on the previous block of ciphertext
	we can simply prepend a random block of data to the message before being encrypted.
	Without the correct IV only the first block is corrupted (The IV acts as a previous CT block)
	and because it contains junk values it can safely be discarded.
	The rest of the message is then returned uncorrupted.
*/

#include <stdio.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char ** argv) {

	// Variables
	uint8_t key[32] = get_key();
	uint8_t IV[32] = get_IV();
	char *msg; // Input message
	char message[32 + strlen(msg)];
	size_t len = strlen(message);
	char *outstr; // Output message
	size_t *outlen;
	char *outmsg; // Decryption message with first block stripped

	// ----- ENCRYPTION ----- //

	// Copy msg to the rest of message for encryption, first 32 byte block just junk
	for (int i = 32; i < (32 + strlen(msg)); i++) {
		message[i] = msg[i - 32];
	}

	AES_CBC_256_encrypt(message, len, key, IV, outstr, outlen);

	// Send it off, store it, etc...

	// ----- DECRYPTION ----- //

	// Receive message, load it, etc...

	AES_CBC_256_decrypt(message, len, key, IV, outstr, outlen);

	// Strip off the junk block
	for (int i = 32; i < outlen; i++) {
		outmsg[i - 32] = outstr[i]; 
	}

	printf(outmsg); // Or whatever else

	return 0;
};
