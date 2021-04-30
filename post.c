#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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

int main(int argc, char ** argv) {

    //char* data = "{ \"result\": [{\"question\":\"autogen-a4-147\",\"format\" : \"tf\",\"answer\" : false},{\"question\":\"autogen-a4-148\",\"format\" : \"mc\",\"answer\" : 0},{\"question\":\"autogen-a4-149\",\"format\" : \"line\",\"answer\" : \"red\"},{\"question\":\"autogen-a4-150\",\"format\" : \"line\",\"answer\" : \"dice\"},{\"question\":\"autogen-a4-151\",\"format\" : \"line\",\"answer\" : \"five\"},{\"question\":\"autogen-a4-152\",\"format\" : \"line\",\"answer\" : \"42\"}] ,\"quiz\" : \"task3\",\"practice\" : false,\"total_questions\" : 7,\"retry\" : true,\"instant\" : false,\"warnzero\" : true,\"duebefore\" : \"2021-04-11 16:00\",\"idnum\" : \"10560\",\"code\" : \"6dc1b25d0fb46e97bfadbdae93698b6c\",\"user\" : \"cody.clark\",\"declare\" : \"Cody Clark\" }";
    char* data = "{ \"result\": [{\"question\":\"autogen-a4-147\",\"format\" : \"tf\",\"answer\" : false}] ,\"quiz\" : \"task3\",\"practice\" : false,\"total_questions\" : 7,\"retry\" : true,\"instant\" : false,\"warnzero\" : true,\"duebefore\" : \"2021-04-11 16:00\",\"idnum\" : \"10560\",\"code\" : \"6dc1b25d0fb46e97bfadbdae93698b6c\",\"user\" : \"cody.clark\",\"declare\" : \"Cody Clark\" }";
    long input_size = strlen(data);
    char* encoded_data = base64_encode(data, input_size, &input_size);
    
    printf("Encoded Data is: %s \n", encoded_data);

    long decode_size = strlen(encoded_data);
    char* decoded_data = base64_decode(encoded_data, decode_size, &decode_size);
    printf("Decoded Data is: %s \n\n", decoded_data);

    char msg[strlen(encoded_data) + 5];
    memset(msg, '\0', sizeof(msg));
    strcpy(msg, "data=");
    strcat(msg, encoded_data);

    char* command = "curl";
    char* op1 = "-X";
    char* op2 = "POST";
    char* op3 = "-d";
    char* url = "https://protest.cpsc.ucalgary.ca/submit.pl";
    char* op4 = "--user";
    char* auth = "Basic:Y29keS5jbGFyazp1dWlpcGF4";
    char* args[] = { command, op1, op2, op3, msg, op4, auth, url, NULL };
    execvp(args[0], args);

	return 0;
}
