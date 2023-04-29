/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	int fd;
	char key[10];
	
	//init
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	
	if(strcmp(argv[1], "-e") == 0){
		printf("========================Encryption========================\n");	
		//open file
		fd = open(argv[2], O_RDONLY);
		printf("open file: %s\n", argv[2]);
		if(fd==-1){
			printf("File Open Error\n");
			return 1;
		}else{
			int templen = read(fd, plaintext, len);
			if(templen==0){
				printf("this file is empty\n");
				return 1;
			}
			close(fd);
		}
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;	
		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		//encrypt:
		//1. generate random key
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GEN, &op,
					 &err_origin);
		//2. encrypt plain text
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		//3. encrypt randomkey by root key
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_KEY, &op,
					 &err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		
		//save ciphertext
		fd = creat("./ciphertext.txt", 0644);
		if(fd==-1){
			printf("File Error: ciphertext\n");
			return 1;
		}else{
			write(fd, ciphertext, strlen(ciphertext));
			close(fd);
		}

		//save root key
		fd = creat("./encryptedkey.txt", 0644);
		if(fd==-1){
			printf("File Error: root key\n");
			return 1;
		}else{
			int tempKey = op.params[1].value.a;
			sprintf(key,"%d",tempKey);
			write(fd, key, strlen(key));
			close(fd);
		}
		
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		return 0;

	}else if(strcmp(argv[1], "-d") == 0){
		printf("========================Decryption========================\n");
		//open Ciphertext file
		fd = open(argv[2], O_RDONLY);
		if(fd==-1){
			printf("File Open Error\n");
			return 1;
		}else{
			int templen = read(fd, ciphertext, len);
			if(templen==0){
				printf("this file is empty\n");
				return 1;
			}
			close(fd);
		}
		
		//open root key file
		fd = open(argv[3], O_RDONLY);
		if(fd==-1){
			printf("File Open Error\n");
			return 1;
		}else{
			int templen = read(fd, key, 2);
			if(templen==0){
				printf("this file is empty\n");
				return 1;
			}
			close(fd);
		}
		op.params[0].tmpref.buffer = ciphertext;
		op.params[0].tmpref.size = len;	
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		op.params[1].value.a = atoi(key);
		
		//decrypt:
		//1. decrypt random key by root key
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_KEY, &op,
					 &err_origin);

		//2. decrytp ciphertext by random key
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);
		
		memcpy(plaintext, op.params[0].tmpref.buffer, len);

		//save plaintext
		fd = creat("./plaintext.txt", 0644);
		if(fd==-1){
			printf("File Error: plaintext\n");
			return 1;
		}else{
			write(fd, plaintext, strlen(plaintext));
			close(fd);
		}

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		return 0;

	}

	return 1;
}

