#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// ----- BASE64 ENCODING ----- //

static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;
static int mod_table[] = { 0, 2, 1 };

void build_decoding_table() {

    decoding_table = malloc(256);

    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char)encoding_table[i]] = i;
}

void base64_cleanup() {
    free(decoding_table);
}

char* base64_encode(const unsigned char* data,
    size_t input_length,
    size_t* output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char* encoded_data = malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

unsigned char* base64_decode(const char* data,
    size_t input_length,
    size_t* output_length) {

    if (decoding_table == NULL) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char* decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
            + (sextet_b << 2 * 6)
            + (sextet_c << 1 * 6)
            + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

// ----- MAIN ----- //

int main(int argc, char** argv) {

    char* fname = "cowrie.json";
    char* pipe = "|";
    int fds[2];
    pipe(fds);

    int opt = atoi(argv[1]);
    
    if (opt == 1) {

        
        if (fork() == 0) {
            // Child process
            close(fds[1]);
            char buffer[256];
            read(fds[0], buffer, sizeof(buffer));
            close(fds[0]);
        }

        // Parent process
        close(fds[0]);

        char* cmd1 = "grep";
        char* instr = "cowrie.login.failed";
        char* cmd2 = "wc";
        char* o2 = "-l";

        char* args[] = { cmd1, instr, fname, pipe, cmd2, o2, NULL };
        execvp(args[0], args);
    }
    /*

        // How many different login names for failed login attempts?
        case 2:
            break;

        // Most popular username for failed login attempts?
        case 3:
            break;

        // How many different IPs for failed login attempts?
        case 4:
            break;

        // What is the most popular IP for failed login attempts?
        case 5:
            break;

        // What is the public ssh key added? (in base64 encoding)
        case 6:
            break;
        default:
            printf("Please run ./A5 <op>\n");
    }
*/
    
    
    

    return 0;



}