#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <time.h>

#define SA struct sockaddr
#define BACKLOG_SIZE 64
#define SRV_ADDR "127.0.0.1"

/*******************************************************************************/
socklen_t len;               // Length of the client address
int sk;                  //  Passive socket
int optval;                  // Socket options
struct sockaddr_in my_addr, cl_addr;      // Client and server addresses
char cl_paddr[INET_ADDRSTRLEN];         // Client IP address
uint16_t cl_port;               // Client port
int ret;
int cl_sk;
int srv_port;
struct sockaddr_in srv_addr;         // Structure for the server IP address
/********************************************************************************/


void print_bytes(const unsigned char* buf, int len)
{
	int i;
	for (i = 0; i < len - 1; i++)
		printf("%02X:", buf[i]);
	printf("%02X", buf[len - 1]);
}

int decrypt(EVP_CIPHER_CTX *ctx, const unsigned char* cphr_buf, int cphr_size, unsigned char* clear_buf, int* clear_size) 
{
	int nd; /* amount of bytes decrypted at each step */
	int ndtot; /* total amount of decrypted bytes */
	int ct_ptr, msg_ptr; /* pointers to the first free location of the buffers */

	int ret;

	nd = 0;
	ndtot = 0;
	ct_ptr = 0;
	msg_ptr =0;

	/* Single step encryption */
	ret = EVP_DecryptUpdate(ctx, clear_buf, &nd, cphr_buf + msg_ptr, cphr_size);
	if(ret == 0)
	{
		printf("\nError: EVP_DecryptUpdate returned %d\n", ret);
      		return 1;
   	}
   	ct_ptr += nd;
   	ndtot += nd;

   	ret = EVP_DecryptFinal(ctx, clear_buf + ct_ptr, &nd);
   	if(ret == 0)
	{
	      printf("\nError: EVP_DecryptFinal returned %d\n", ret);
	      return 1;
	}
   	ndtot += nd;

   	*clear_size = ndtot;

   	return 0;
}


int recv_buffer(int sk, unsigned char** buf, int* buf_len)
{
	int ret;

	//receiving the lenght of the data sent
	ret = recv(sk, buf_len, sizeof(*buf_len), MSG_WAITALL);
	if (ret<sizeof(*buf_len))
	{
		printf("Error in receiving the lenght of data(buf)...\n");
		return 1;
	}

	*buf = malloc(*buf_len);

	//receiving the data
	ret = recv(sk, *buf, *buf_len, MSG_WAITALL);
	if (ret<*buf_len)
	{
		printf("Error in receiving data(buf)...\n");
		return 1;
	}

	return 0;
}

int retrieve_key(char* key,int key_len, char* file_name)
{

	FILE* file;
	int ret;

	file=fopen(file_name,"r");
	if (file==NULL)
	{
		printf("Errore sull'apertura del file (%s)...\n", file_name);
		return 1;
	}

	rewind(file);

	ret = fread(key, 1, key_len, file);
	fclose (file);

	if(ret < key_len)
      		return 1;

	return 0;
}


int manage_server(int argc, char*argv[])
{
    //controlli sui parametri

	if(argc != 2)
	{
     	 	printf("Port number is not correct!\n ");
      		return 1;
   	}

   	if(atoi(argv[1]) < 1024 || atoi(argv[1]) > 65535)
	{
      		printf("Port number is not valid\n");
      		return 1;
   	}

   	srv_port = atoi(argv[1]);

   	memset(&srv_addr, 0, sizeof(srv_addr));
   	srv_addr.sin_family = AF_INET;
   	srv_addr.sin_port = htons(srv_port);
   	ret = inet_pton(AF_INET, SRV_ADDR, &srv_addr.sin_addr);
   	if(ret <= 0)
	{
     		printf("Address is not correct\n");
      		return 1;
   	}

// creazione del socket
   	sk = socket(AF_INET, SOCK_STREAM, 0);
   	if(sk == -1)
	{
     	 	printf("Error on socket()\n");
      		return 1;
   	}

   	optval = 1;
   	ret = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
   	if(ret == -1)
	{
      		printf("Error on setsockopt()\n");
      		return 1;
   	}

   	memset(&my_addr, 0, sizeof(my_addr));
   	my_addr.sin_family = AF_INET;
   	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   	my_addr.sin_port = htons(srv_port);

   	ret = bind(sk, (SA*)&my_addr, sizeof(my_addr));
   	if(ret == -1)
	{
      		printf("Error on bind().\n");
      		return 1;
   	}

   	ret = listen(sk, BACKLOG_SIZE);
   	if(ret == -1)
	{
      		printf("Error on backlog size\n" );
      		return 1;
   	}

  	printf("\nWaiting for a connection...\n");

	len = sizeof(cl_addr);
	cl_sk = accept(sk, (SA*)&cl_addr, &len);

	if(cl_sk == -1)
	{
		printf("Error on accept().\n");
        	return 1;
    	}

   	inet_ntop(AF_INET, &cl_addr.sin_addr, cl_paddr, sizeof(cl_paddr));
    	cl_port = ntohs(cl_addr.sin_port);
    	printf("\nConnection established with client %s on port %d...\n",  SRV_ADDR, cl_port);

    	return 0;
}

int save_document(unsigned char* plaintext, int plaintext_size, char* name)
{
	FILE* file;

    	file = fopen(name, "w");
    	if(file == NULL)
    	{
    	    printf("\nError in opening the file...\n");
    	    return 1;
    	}

	rewind(file);
    	ret = fwrite(plaintext, 1, plaintext_size, file);
    	if(ret < plaintext_size)
    	{
    	    printf("\nError in writing on the file...\n");
    	    return 1;
    	}
    	plaintext[plaintext_size] = '\0';

    	printf("Text written in file \"%s\"\n\n", name);

    	fclose(file);

   	return 0;
}

int main(int argc, char*argv[])
{
	int ret;
	char* app;

	unsigned char* my_msg;
	int my_msg_len;	
	unsigned char* M3_plaintext;
	int M3_plaintext_len;
	char other;
	time_t tick;
	time_t rec_tick;
	double diff;	

	unsigned char* ciphertext;
	int ciphertext_len;
    	unsigned char* plaintext;
	int plaintext_len;

	char* key;
	char* file_name;
	int key_size;
	char* key2_file;
	char* key12_file;
	char* symmetric_key;
	EVP_CIPHER_CTX* ctx;
	const EVP_CIPHER* cipher = EVP_des_cbc();

	FILE* file;

   	printf("\nServer is active on port %d\n",atoi(argv[1]));

    	while(1)
    	{
        	ret = manage_server(argc, argv);
		close(sk);
        	if (ret==1)
        	{
        	    	printf("Error in managing the server");
			close(cl_sk);
        	    	continue;
        	}

		ret = recv_buffer(cl_sk, &my_msg, &my_msg_len);
        	if (ret==1)
        	{
        	    	printf("M3 not received\n");
			close(cl_sk);
        	    	continue;
        	}

		key_size = EVP_CIPHER_key_length(EVP_des_cbc());
		key=malloc(key_size);
	
		app = argv[0];
		key2_file = malloc(5);
		memcpy(key2_file, "Key", 3);
		memcpy(key2_file+3, &app[2], 1);
		key2_file[4] = '\0';

		ret = retrieve_key(key, key_size, key2_file);
		if (ret == 1)
		{
			printf("Error in retrieving the key...\n");
			close(cl_sk);
			continue;
		}

		ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_init(ctx);	//context init
		ret = EVP_DecryptInit(ctx, cipher, (unsigned char*)key, NULL);
		if (ret == 0)
		{
			printf("Error in initializing the context...\n");
			close(cl_sk);
			continue;
		}

		M3_plaintext_len = my_msg_len;
		M3_plaintext = (unsigned char*)malloc(M3_plaintext_len);
	
		ret = decrypt(ctx, my_msg, my_msg_len, M3_plaintext, &M3_plaintext_len);
		if (ret == 1)
		{
			printf("Error in decrypting the file...");
			close(cl_sk);
			continue;
		}


		//check on message received
		app = argv[0];
		if (M3_plaintext[1]!=app[2])
		{
			printf("Error in the protocol!\n");
			close(cl_sk);
			continue;
		}

		memcpy((void*)&rec_tick, M3_plaintext+sizeof(char)+sizeof(char)+key_size, sizeof(time_t));
		tick = time(NULL);
		diff = difftime(tick, rec_tick);
		if (diff>120)
		{
			printf("Message may not be fresh...\n");
			close(cl_sk);
			continue;
		}

		other = M3_plaintext[0];

		//saving the key
		symmetric_key = malloc(key_size);
		memcpy(symmetric_key, M3_plaintext+sizeof(char)+sizeof(char), key_size);


		key12_file = malloc(6);
		app = argv[0];
		memcpy(key12_file, "Key", 3);
		memcpy(key12_file+3, &other, 1);
		memcpy(key12_file+4, &app[2], 1);
		key12_file[5]='\0';
		file = fopen(key12_file, "w");
		if (file==NULL)
		{
			printf("Error in opening the file...\n");
			close(cl_sk);
			continue;
		}
		rewind(file);
		ret = fwrite(symmetric_key, 1, key_size, file);
		if (ret<key_size)
		{
			printf("Error in writing in the file...\n");
			close(cl_sk);
			continue;
		}
		fclose(file);
		printf("Key received and saved locally...\n"); 

	
		//Receiving the ciphertext		
		ret = recv_buffer(cl_sk, &ciphertext, &ciphertext_len);
        	if (ret==1)
        	{
        	    	printf("Error: ciphertext not received...\n");
			close(cl_sk);		
        	    	continue;
        	}

		ctx = malloc(sizeof(EVP_CIPHER_CTX));
        	EVP_CIPHER_CTX_init(ctx);
        	ret = EVP_DecryptInit(ctx, cipher, (const unsigned char*)symmetric_key, NULL);
        	if(ret == 0)
		{
        		printf("\nError: EVP_DecryptInit returned %d\n", ret);
			close(cl_sk);
            		continue;
        	}

       		 /* Allocating the buffer for the plaintext */
        	plaintext = malloc(ciphertext_len);
        	if(plaintext == NULL) 
		{
	        	printf("\nError allocating the buffer for the plaintext\n");
			close(cl_sk);
        		continue;
       		}

        	ret = decrypt(ctx, ciphertext, ciphertext_len, plaintext, &plaintext_len);
        	if(ret != 0)
		{
       			close(cl_sk);
			continue;
		}
        	EVP_CIPHER_CTX_cleanup(ctx);
        	free(ctx);

        	printf("Plaintext obtained correctly...\n");

       		file_name="output.txt";
        	ret=save_document(plaintext, plaintext_len, file_name);
	}

   	return 0;
}
