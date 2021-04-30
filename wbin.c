// Author: Cody Clark
/*
    This program creates two binary files which differ in their content but are an MD5 collision.
    Using a strange file format certain strings are able to be read, but this file format results in
    susceptibility to a length extension attack.

    Written for CPSC 526 Network Security Winter2021
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct fformat {
    // Magic numbers
	unsigned char mn1;
	unsigned char mn2;
	unsigned char mn3;
	// Big-Endian file length
	unsigned char lenh; // File length high
	unsigned char lenl; // File length low
	// Reserved bytes
	unsigned char res[14];
	// Offset jump Big Endian
	unsigned char jumph; //
	unsigned char jumpl;
	// Rest of the MD5 collision
	unsigned char rest[107];
    // Space, second message length in big endian, then second message (Z-)
	unsigned char a[264];
	unsigned char dlh2; // Message length high
	unsigned char dll2; // Message length low
	char msg2[40];
	// Space, first message length in big endian, and then first message (A+)
	unsigned char b[112];
	unsigned char dlh1; // Message length high
	unsigned char dll1; // Message length low
	char msg1[40];
	// Last space to fill file length of 709 bytes
	unsigned char c[121];
};

void setc1(struct fformat * c1, char * res, char * rest);
void setc2(struct fformat * c2, char * res, char * rest);

int main(void) {
	char f1[] = "f1.bin";
	char f2[] = "f2.bin";

	char res[] = { 0xe6, 0xee, 0xc4, 0x69, 0x3d, 0x9a, 0x06, 0x98, 0xaf, 0xf9, 0x5c, 0x2f, 0xca, 0xb5 };
	char rest1[] = { 0x46, 0x7e, 0xab, 0x40, 0x04, 0x58, 0x3e, 0xb8, 0xfb,
	                 0x7f, 0x89, 0x55, 0xad, 0x34, 0x06, 0x09, 0xf4, 0xb3, 0x02, 0x83,
	                 0xe4, 0x88, 0x83, 0x25, 0x71, 0x41, 0x5a, 0x08, 0x51, 0x25, 0xe8,
	                 0xf7, 0xcd, 0xc9, 0x9f, 0xd9, 0x1d, 0xbd, 0xf2, 0x80, 0x37, 0x3c,
	                 0x5b, 0xd8, 0x82, 0x3e, 0x31, 0x56, 0x34, 0x8f, 0x5b, 0xae, 0x6d,
	                 0xac, 0xd4, 0x36, 0xc9, 0x19, 0xc6, 0xdd, 0x53, 0xe2, 0xb4, 0x87,
	                 0xda, 0x03, 0xfd, 0x02, 0x39, 0x63, 0x06, 0xd2, 0x48, 0xcd, 0xa0,
	                 0xe9, 0x9f, 0x33, 0x42, 0x0f, 0x57, 0x7e, 0xe8, 0xce, 0x54, 0xb6,
	                 0x70, 0x80, 0xa8, 0x0d, 0x1e, 0xc6, 0x98, 0x21, 0xbc, 0xb6, 0xa8,
	                 0x83, 0x93, 0x96, 0xf9, 0x65, 0x2b, 0x6f, 0xf7, 0x2a, 0x70 };

    char rest2[] = { 0x46, 0x7e, 0xab, 0x40, 0x04, 0x58, 0x3e, 0xb8, 0xfb,
                     0x7f, 0x89, 0x55, 0xad, 0x34, 0x06, 0x09, 0xf4, 0xb3, 0x02, 0x83,
                     0xe4, 0x88, 0x83, 0x25, 0xf1, 0x41, 0x5a, 0x08, 0x51, 0x25, 0xe8,
                     0xf7, 0xcd, 0xc9, 0x9f, 0xd9, 0x1d, 0xbd, 0x72, 0x80, 0x37, 0x3c,
                     0x5b, 0xd8, 0x82, 0x3e, 0x31, 0x56, 0x34, 0x8f, 0x5b, 0xae, 0x6d,
                     0xac, 0xd4, 0x36, 0xc9, 0x19, 0xc6, 0xdd, 0x53, 0xe2, 0x34, 0x87,
                     0xda, 0x03, 0xfd, 0x02, 0x39, 0x63, 0x06, 0xd2, 0x48, 0xcd, 0xa0,
                     0xe9, 0x9f, 0x33, 0x42, 0x0f, 0x57, 0x7e, 0xe8, 0xce, 0x54, 0xb6,
                     0x70, 0x80, 0x28, 0x0d, 0x1e, 0xc6, 0x98, 0x21, 0xbc, 0xb6, 0xa8,
                     0x83, 0x93, 0x96, 0xf9, 0x65, 0xab, 0x6f, 0xf7, 0x2a, 0x70 };

    // Collision part 1
	struct fformat col1;
	setc1(&col1, res, rest1);

    // Collision part 2
	struct fformat col2;
	setc2(&col2, res, rest2);

    // Write the respective files
	FILE * fp1 = fopen(f1, "wb");
	if (!fp1) {
		printf("Unable to open file!\n");
		return 1; // return 1
	}
	fseek(fp1, 0, SEEK_SET);
	fwrite(&col1, sizeof(struct fformat), 1, fp1);
	fclose(fp1);

	FILE * fp2 = fopen(f2, "wb");
	if (!fp2) {
		printf("Unable to open file!\n");
		return 1;
	}
	fseek(fp2, 0, SEEK_SET);
	fwrite(&col2, sizeof(struct fformat), 1, fp2);
	fclose(fp2);

	return 0; // return 0
};

// Fill in the collisions

void setc1(struct fformat * c1, char * res, char * rest) {
	c1->mn1 = 0xd1;
	c1->mn2 = 0x31;
	c1->mn3 = 0xdd;
	c1->lenh = 0x02;
	c1->lenl = 0xc5;
	memcpy(c1->res, res, 14);
	c1->jumph = 0x87;
	c1->jumpl = 0x12;
	memcpy(c1->rest, rest, 107);
	memset(c1->msg1, 0, sizeof(c1->msg1));
	memset(c1->msg2, 0, sizeof(c1->msg2));
	strcpy(c1->msg1, "30010560 will receive an A+ in CPSC 526");
	c1->dlh1 = 0x00;
	c1->dll1 = strlen(c1->msg1);
	strcpy(c1->msg2, "30010560 will receive a Z- in CPSC 526");
    c1->dlh2 = 0x00;
    c1->dll2 = strlen(c1->msg2);
	memset(c1->a, 0, sizeof(c1->a));
    memset(c1->b, 0, sizeof(c1->b));
    memset(c1->c, 0, sizeof(c1->c));
};

void setc2(struct fformat * c2, char * res, char * rest) {
	c2->mn1 = 0xd1;
	c2->mn2 = 0x31;
	c2->mn3 = 0xdd;
	c2->lenh = 0x02;
	c2->lenl = 0xc5;
	memcpy(c2->res, res, 14);
	c2->jumph = 0x07;
	c2->jumpl = 0x12;
	memcpy(c2->rest, rest, 107);
    memset(c2->msg1, 0, sizeof(c2->msg1));
    memset(c2->msg2, 0, sizeof(c2->msg2));
	strcpy(c2->msg1, "30010560 will receive an A+ in CPSC 526");
    c2->dlh1 = 0x00;
    c2->dll1 = strlen(c2->msg1);
    strcpy(c2->msg2, "30010560 will receive a Z- in CPSC 526");
    c2->dlh2 = 0x00;
    c2->dll2 = strlen(c2->msg2);
	memset(c2->a, 0, sizeof(c2->a));
	memset(c2->b, 0, sizeof(c2->b));
	memset(c2->c, 0, sizeof(c2->c));
};
