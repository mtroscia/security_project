#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define SA struct sockaddr

int cl_port;    /* Port number */
int sk;       /* Communication socket */
unsigned char* oth_msg;
int oth_msg_len;
char* other_par[3];

struct sockaddr_in srv_addr;
struct sockaddr_in other_addr;

void print_bytes(const unsigned char* buf, int len) 
{
	int i;
	for (i = 0; i < len - 1; i++)
		printf("%02X:", buf[i]);
   	printf("%02X", buf[len - 1]);
}

int retrieve_key(unsigned char* key, const int key_size, char* file_name)
{
	int ret;
	FILE* file;

	file = fopen(file_name, "r");
	if (file==NULL)
	{
		printf("Error in opening the key file %s...\n", file_name);
		return 1;
	}

	rewind(file);

	ret = fread(key, 1, key_size, file);
	fclose(file);
	if (ret<key_size)
	{
		printf("Error in retrieving the key...\n");
		return 1;
	}
	return 0;
}

int encrypt(EVP_CIPHER_CTX *ctx, const unsigned char* plaintext, int plaintext_size, unsigned char* ciphertext, int* ciphertext_size) 
{
	int ciphertext_pointer; /* pointers to the first free location of the buffers */

	int num; /* amount of bytes encrypted at each step */
	int tot; /* total amount of encrypted bytes */

	int ret;

    	num = 0;
    	tot= 0;
    	ciphertext_pointer = 0;


    	ret = EVP_EncryptUpdate(ctx, ciphertext, &num, plaintext, plaintext_size);
   	if(ret == 0)
	{
      		printf("\nError: EVP_EncryptUpdate returned %d\n", ret);
      		return 1;
   	}
   	ciphertext_pointer+= num;
   	tot += num;

   	ret = EVP_EncryptFinal(ctx, ciphertext + ciphertext_pointer, &num);
   	if(ret == 0)
	{
	      printf("\nError: EVP_EncryptFinal returned %d\n", ret);
	      return 1;
	}
	tot += num;

   	*ciphertext_size = tot;

   	return 0;
}

int send_buffer(int sk, const unsigned char* buf, int buf_len)
{
	int ret;

	//sending the lenght of the data to send
	ret = send(sk, &buf_len, sizeof(buf_len), 0);
	if (ret < sizeof(buf_len))
	{
		printf("Error in sending the lenght of data...\n");
		return 1;
	}

	//sending the data
	ret = send(sk, buf, buf_len, 0);
	if (ret<buf_len)
	{
		printf("Error in sending data...\n");
		return 1;
	}

	return 0;
}

int decrypt(EVP_CIPHER_CTX* ctx, const unsigned char* ciphertext, const int ciphertext_len, unsigned char* plaintext, int* plaintext_len)
{
	int ret;	

	int outlen;
	int outlen_tot;

	outlen = 0;
	outlen_tot = 0;

	/*****************/	
	ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
	if(ret == 0)
	{
      		printf("Error in updating the context...\n");
      		return 1;
   	}
	outlen_tot += outlen;
	/****************/

	ret = EVP_DecryptFinal(ctx, plaintext+outlen_tot, &outlen);
	if(ret == 0){
      		printf("\nError in finalizing the context...\n");
      		return 1;
   	}
	outlen_tot += outlen;

	*plaintext_len = outlen_tot;

	return 0;
}

int recv_buffer(int sk, unsigned char** buf, int* buf_len)
{
	int ret;

	//receiving the lenght of the data sent
	ret = recv(sk, buf_len, sizeof(*buf_len), MSG_WAITALL);
	if (ret<sizeof(*buf_len))
	{		
		printf("Error in receiving the lenght of data...\n");
		return 1;
	}

	*buf = malloc(*buf_len);

	//receiving the data
	ret = recv(sk, *buf, *buf_len, MSG_WAITALL);
	if (ret<*buf_len)
	{
		printf("Error in receiving data...\n");
		return 1;
	}

	return 0;
}

int recv_string(int sk, char** str, int* str_len)
{
	int ret;

	//receiving the lenght of the data sent
	ret = recv(sk, str_len, sizeof(*str_len), MSG_WAITALL);
	if (ret!=sizeof(*str_len))
	{
		printf("Error in receiving the lenght of data...\n");
		return 1;
	}

	*str = malloc(*str_len+1);
	
	//receiving the data
	ret = recv(sk, *str, *str_len, MSG_WAITALL);
	if (ret < *str_len)
	{
		printf("Error in receiving data...\n");
		return 1;
	}

	(*str)[*str_len]='\0';

	return 0;
}

int open_file(unsigned char** plaintext_buf,const char* send_file_name, int* send_file_size)
{
	int  ret;
	FILE* file;

	file = fopen(send_file_name, "r");
   	if(file == NULL)
	{
      		printf("\nFile %s not found!\n", send_file_name);
      		return 1;
   	}


   	fseek(file, 0, SEEK_END);  
   	*send_file_size = ftell(file); 
   	fseek(file, 0, SEEK_SET); 

	*plaintext_buf = (unsigned char*)malloc(*send_file_size+1);
   	ret = fread(*plaintext_buf, 1, *send_file_size, file);
   	if(ret < *send_file_size)
	{
      		printf("\nError in reading the content of file %s...\n", send_file_name);
      		return 1;
   	}


   	fclose(file);

	return 0;
}

int send_document(const char* send_file_name, const char* key_file_name)
{
   	int send_file_size;

    	const EVP_CIPHER* cipher = EVP_des_cbc();
   	EVP_CIPHER_CTX* ctx;   

	int symmetric_key_size=EVP_CIPHER_key_length(cipher);
	unsigned char* symmetric_key= malloc(symmetric_key_size);

	unsigned char* plaintext_buf;      // buffer to contain the file + the digest
   	unsigned char* ciphertext_buf;   // buffer to contain the ciphertext
   	int ciphertext_size;   // size of the ciphertext
   	int block_size;
	int ret;

   	ret = retrieve_key(symmetric_key, symmetric_key_size, (char*) key_file_name);
   	if(ret != 0)
	{
		printf("Symmetric key wasn't retrieved...\n");
      		return 1;
   	}

	ret=open_file(&plaintext_buf, send_file_name, &send_file_size);
	if (ret==1)
		return 1;

	printf("\nPlaintext retrieved correctly...\n");


   	ctx = malloc(sizeof(EVP_CIPHER_CTX));
   	EVP_CIPHER_CTX_init(ctx);
   	ret = EVP_EncryptInit(ctx, cipher, symmetric_key, NULL);
   	if(ret == 0)
   	{
   	    printf("Error on  EVP_EncryptInit()\n");
   	    return 1;
  	}


    	block_size = EVP_CIPHER_block_size(cipher);
    	ciphertext_size = send_file_size + block_size;
    	ciphertext_buf = malloc(ciphertext_size);
    	if(ciphertext_buf == NULL)
    	{
        	printf("Allocation error...\n");
        	return 1;
    	}

    	ret = encrypt(ctx, plaintext_buf, send_file_size, ciphertext_buf, &ciphertext_size);
    	if(ret != 0)
    	{
    	    printf("Error on encrypt()");
    	    return 1;
    	}

    	EVP_CIPHER_CTX_cleanup(ctx);
    	free(ctx);

	//transmission of the ciphertext
	ret = send_buffer(sk, ciphertext_buf, ciphertext_size);
	if (ret == 1)
	{
		printf("It wasn't possible to send the ciphertext...\n");
		return 1;
	}
	printf( "Ciphertext sent correctly...\n");

	return 0;
}

int ask_key(char** argv)
{
	unsigned char* buffer;
	int buffer_len;
	int ret;
	char* app;
	unsigned char* my_msg;
	int my_msg_len;

	EVP_CIPHER_CTX* ctx; 
	int block_size; 
	const EVP_CIPHER* cipher = EVP_des_cbc();
	unsigned char* plaintext;
	int plaintext_len;
	char* key;
	int key_size;
	char* key1_file;
	char* key12_file;

	unsigned char* k12;
	time_t rec_tick;
	time_t tick;
	double diff;

	FILE* file;

	//SENDING M1 A->T: A,B
	buffer_len = sizeof(char)*2;
	buffer = malloc(buffer_len);
	app = malloc(5);
	app = argv[0];
	buffer[0] = app[2];
	buffer[1] = *other_par[0];

	printf("\nRequesting a key to talk with %c\n", buffer[1]);
	ret = send_buffer(sk, buffer, buffer_len);
	if (ret==1)
	{
		printf("Error in sending the request to T...\n");
		return 1;
	}

	//RECEIVING M2 T->A
	ret = recv_buffer(sk, &oth_msg, &oth_msg_len);
	if (ret==1)
	{
		printf("Error in receiving the data...\n");
		return 1;
	}
	
	//RECEIVING M3 T->A
	ret = recv_buffer(sk, &my_msg, &my_msg_len);
	if (ret==1)
	{
		printf("Error in receiving the data...\n");
		return 1;
	}
	
	//retrieving kA and decrypting the message received
	key_size = EVP_CIPHER_key_length(cipher);
	key=malloc(key_size);
	app = argv[0];
	key1_file = malloc(4);
	memcpy(key1_file, "Key", 3);
	memcpy(key1_file+3, &app[2], 1);	

	ret = retrieve_key(key, key_size, key1_file);
	if (ret == 1)
	{
		printf("Error in retrieving the key...");
		return 1;
	}

	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);	
	ret = EVP_DecryptInit(ctx, cipher, (unsigned char*)key, NULL);
	if (ret == 0)
	{
		printf("Error in initializing the context...\n");
		return 1;
	}

	plaintext_len = my_msg_len;
	plaintext = (unsigned char*)malloc(plaintext_len);
	
	ret = decrypt(ctx, my_msg, my_msg_len, plaintext, &plaintext_len);
	if (ret == 1)
	{
		printf("Error in decrypting the file...");
		return 1;
	}

	//checks on received message
	if (plaintext[0]!=*other_par[0])
	{
		printf("Error in the protocol!\n");
		return 1;
	}

	memcpy((void*)&rec_tick, plaintext+sizeof(char)+key_size, sizeof(time_t));
	tick = time(NULL);
	diff = difftime(tick, rec_tick);
	if (diff>120)
	{
		printf("Message may not be fresh...\n");
		return 1;
	}

	//saving the key
	k12 = malloc(key_size);
	memcpy(k12, plaintext+sizeof(char), key_size);
	
	key12_file = malloc(5);
	memcpy(key12_file, key1_file, 4);
	memcpy(key12_file+4, other_par[0], 1);
	file = fopen(key12_file, "w");
	if (file==NULL)
	{
		printf("Error in opening the file of the symmetric key...\n");
		return 1;
	}

	rewind(file);
	ret = fwrite(k12, 1, key_size, file);
	if (ret<key_size)
	{
		printf("Error in writing in the file...\n");
		return 1;
	}
	fclose(file);
	printf("Key received and saved locally...\n"); 

	return 0;
}

int manage_client(int argn, char* args[])
{
	int ret;     

   	struct sockaddr_in srv_addr;      /* Server address */

   	cl_port = atoi(args[2]);

	memset(&srv_addr, 0, sizeof(srv_addr)); 
   	srv_addr.sin_family = AF_INET; 
   	srv_addr.sin_port = htons(cl_port); 
   	ret = inet_pton(AF_INET, args[1], &srv_addr.sin_addr);
   	if(ret <= 0) 
	{
      		printf("Address is not correct\n");
      		return 1;
  	}


	//connection
   	sk = socket(AF_INET, SOCK_STREAM, 0);
   	if(sk == -1) 
	{
      		printf("Error creating the socket...\n");
     		return 1;
	}

   	ret = connect(sk, (SA*)&srv_addr, sizeof(srv_addr));
   	if(ret == -1) 
	{
      		printf("\nError on connect().\n");
      		return 1;
   	}

   	printf("Connection established with %s on port %d...\n", args[1], cl_port);

	return 0;
}

int main(int argc, char*argv[]) 
{
	int ret;
	char* file_name; //file containing the text to send
	char* key_file_name;	//file containing the key
	char* app;
	char other;
	FILE* file;
	char* all_zero;
	const EVP_CIPHER* cipher = EVP_des_cbc();
	int key_size = EVP_CIPHER_key_length(cipher);

	//check on arguments
   	if(argc != 3)
	{
      		printf ("Wrong number of arguments\n");
		printf ("Usage: ./<my_name> <T_address> <T port>\n\n");
      		return 1;
   	}

   	if(atoi(argv[2])<1024 || atoi(argv[2])>65535) 
	{
      		printf ("Port number is not a valid one\n");
		printf ("It should be greater than 1024 and less than 65535\n");
      		return 1;
   	}

	printf("\nInsert the user you want to talk to:\t");
	scanf("%c", &other);
	other_par[0] = &other;
	printf("Its address:\t\t\t\t");
	other_par[1] = malloc(16);
	scanf("%s", other_par[1]);
	printf("Its port:\t\t\t\t");
	other_par[2] = malloc(6);
	scanf("%s", other_par[2]);
	printf("\n\n");

	if(atoi(other_par[2])<1024 || atoi(other_par[2])>65535)
	{
      		printf ("Port number is not a valid one\n");
		printf ("It should be greater than 1024 and less than 65535\n");
      		return 1;
   	}

	ret = manage_client(argc, argv);
	if (ret==1)
	{
		printf("Error while connecting with T...");
		return 1;
	}

	ret = ask_key(argv);
	if (ret==1)
	{
		printf("Error in asking the key to talk with %c...\n", other_par[0][0]);
		return 1;
	}

	printf("\n\nStarting a connection with %c...\n", other_par[0][0]); 

	ret = manage_client(3, other_par);
	if (ret==1)
	{
		printf("Error on connection with %c\n", other_par[0][0]);
		return 1;
	}

	//sending M3 A->B: {A,B,kAB,t}kB
	ret = send_buffer(sk, oth_msg, oth_msg_len);
	if (ret==1)
	{
		printf("Error in sending the message to %c...\n", other_par[0][0]);
		return 1;
	}

    	file_name=malloc(30);
    	printf("Insert the name of the file to send to %c:\t", other_par[0][0]);
    	scanf("%s", file_name);

	key_file_name=malloc(5);
	
	memcpy(key_file_name,"Key", 3);
	app = argv[0];
	memcpy(key_file_name+3, &app[2], 1);		
	memcpy(key_file_name+4, &other_par[0][0], 1);

	//send file encrypted with symmetric key
	ret = send_document(file_name, key_file_name);
   	if(ret != 0)
	{
     		printf("\nError in sending the document to %c...\n", other_par[0]);
      		return 1;
	}
	printf("\n");
	
	//reset the key and delete the key file
	file = fopen(key_file_name, "w");
	if (file==NULL)
	{
		printf("Error in opening the file of the symmetric key...\n");
		return 1;
	}
	rewind(file);
	all_zero = malloc(key_size);
	all_zero = "00000000";
	ret = fwrite(all_zero, 1, key_size, file);
	if (ret<key_size)
	{
		printf("Error in resetting the key file...\n");
		return 1;
	}
	fclose(file);
	
	ret = remove(key_file_name);
	if (ret==-1)
	{
		printf("Error in deleting the file...\n");
		return 1;
	}
	printf("All done! Closing...\n");

   	return 0;
}
