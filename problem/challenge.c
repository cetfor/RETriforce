#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * compiled with:
 * gcc -O0 -fno-stack-protector -o sample sample.c
 */

int main(int argc, char** argv)
{
	// flag: "flag{cyb3rsp4c3_c4mp}"
	char flag[32] = { 0 };

	flag[0] = 'f';
	flag[1] = 'l';
	flag[2] = 'a';
	flag[3] = 'g';
	flag[4] = '{';

	// c
	flag[5] = 20;
	flag[5] = flag[5] * 5;
	flag[5] = flag[5] - 1;

	// y
	flag[6] = 110;
	flag[6] = flag[6] ^ 23;

	// b
	flag[7] = 98;
	flag[7] = flag[7] >> 2;
	flag[7] = flag[7] * 4;
	flag[7] = flag[7] + 2;

	// 3
	flag[8] = 48;
	flag[8] = flag[8] << 2;
	flag[8] = flag[8] | 15;
	flag[8] = flag[8] - 156;

	// r
	flag[9] = 14;
	for(int i=0; i<100; i++)
	{
		flag[9] = flag[9] + 1;
	}

	// s
	flag[10] = 255;
	flag[10] = flag[10] / 4;
	flag[10] = flag[10] >> 2;
	flag[10] = flag[10] + 115;

	// p
	flag[11] = 255;
	flag[11] = flag[11] - 252;
	flag[11] = flag[11] * 37;
	flag[11] = flag[11] + 10;
	flag[11] = flag[11] - 9;

	// 4
	flag[12] = 3;
	flag[12] = flag[12] << 4;
	flag[12] = flag[12] | 4;

	// c
	flag[13] = 20;
	flag[13] = flag[13] * 5;
	flag[13] = flag[13] - 1;

	// 3
	flag[14] = 48;
	flag[14] = flag[14] << 2;
	flag[14] = flag[14] | 15;
	flag[14] = flag[14] - 156;

	// _
	flag[15] = flag[13];
	flag[15] = flag[15] - 4;

	// c
	flag[16] = 20;
	flag[16] = flag[16] * 5;
	flag[16] = flag[16] - 1;

	// 4
	flag[17] = 3;
	flag[17] = flag[17] << 4;
	flag[17] = flag[17] | 4;

	// m
	flag[18] = 100;
	flag[18] = flag[18] + 10;
	flag[18] = flag[18] - 1;

	// p
	flag[19] = 255;
	flag[19] = flag[19] - 252;
	flag[19] = flag[19] * 37;
	flag[19] = flag[19] + 10;
	flag[19] = flag[19] - 9;

	flag[20] = '}';
	
	printf("%s\n", flag);

	return 0;
}
