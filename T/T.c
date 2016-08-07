#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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

   fd_set master, read_fds;
   int fd_max;
/********************************************************************************/

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
		printf("Error in opening the key file...\n");
		return 1;
	}

	ret = fread(key, 1, key_size, file);
	fclose(file);
	if (ret<key_size)
	{
		printf("Error in retrieving the key...\n");
		return 1;
	}
	return 0;
}

int encrypt(EVP_CIPHER_CTX* ctx, const unsigned char* plaintext, const int plaintext_len, unsigned char* ciphertext, int* ciphertext_len)
{
	int ret;	
	int outlen;
	int outlen_tot;

	outlen = 0;
	outlen_tot = 0;
	
	ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, (unsigned char*)plaintext, plaintext_len);
	if (ret==0)
	{
		printf("Error in updating the context...\n");
		return 1;
	}
	outlen_tot += outlen;

	EVP_EncryptFinal(ctx, ciphertext+outlen_tot, &outlen);
	if (ret==0)
	{
		printf("Error in finalizing the context...\n");
		return 1;
	}
	outlen_tot += outlen;

	*ciphertext_len = outlen_tot;

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

int recv_string(int sk, char** str, int* str_len)
{
	int ret;

	//receiving the lenght of the data sent
	ret = recv(sk, str_len, sizeof(*str_len), MSG_WAITALL);
	if (ret!=sizeof(*str_len))
	{
		printf("Error in receiving the lenght of data(string)...\n");
		return 1;
	}

	*str = malloc(*str_len+1);
	
	//receiving the data
	ret = recv(sk, *str, *str_len, MSG_WAITALL);
	if (ret < *str_len)
	{
		printf("Error in receiving data...(string)\n");
		return 1;
	}

	(*str)[*str_len]='\0';

	return 0;
}

int send_key(sk)
{
	unsigned char* buffer;
	unsigned char first;
	unsigned char second;
	char* str;
	char* KeyFirst;
	char* KeySecond;
	int len;
	int buffer_len;
	int ret;

	unsigned char* key1;
	unsigned char* key2;
	unsigned char* key12;
	int key_len;

	EVP_CIPHER_CTX* ctx; 
	int block_size; 
	const EVP_CIPHER* cipher = EVP_des_cbc();
	unsigned char* ciphertext;
	int ciphertext_len;

	time_t tick;

	FILE* file;

	//RECEIVING M1 A->T: A,B
	ret = recv_buffer(sk, &buffer, &buffer_len);
	if (ret==1)
	{
		printf("Error in receiving the data...\n");
		return 1;
	}	

	first = buffer[0];
	second = buffer[1];
	KeyFirst = NULL;
	KeySecond = NULL;
	
	//check if keys to communicate with first and second exist and retrieve them
	file = fopen("Database", "r");
	if (file==NULL)
	{
		printf("Error in opening the Database...\n");
		return 1;
	}

	str = malloc(20);
	while(fscanf(file,"%s", str)!=EOF)
	{
		if (str[0]==first)
		{
			len = strlen(str)-2+1;
			KeyFirst = malloc(len);
			memcpy(KeyFirst, str+2, len);
		}
		else if (str[0]==second)
		{
			len = strlen(str)-2+1;
			KeySecond = malloc(len);
			memcpy(KeySecond, str+2, len);	
		}
	}	

	if (KeyFirst==NULL)
	{
		printf("Error: user %c not found in the database!\n", first);
		return 1;
	}
	else if (KeySecond==NULL)
	{
		printf("Error: user %c not found in the database!\n", second);
		return 1;
	}
	else
		printf("%c wish to communicate with %c\n", first, second);

	key_len = EVP_CIPHER_key_length(cipher);
	key1 = malloc(key_len);
	ret = retrieve_key(key1, key_len, KeyFirst);
	if (ret==1)
	{
		printf("Error in retrieving the key of the first...\n");
		return 1;
	}
	key2 = malloc(key_len);
	ret = retrieve_key(key2, key_len, KeySecond);
	if (ret==1)
	{
		printf("Error in retrieving the key of the second...\n");
		return 1;
	}

	
	//PREPARE THE BUFFERS
	
	//generate a key
	key12 = malloc(key_len);	
	RAND_bytes(key12, key_len);	
	
	//generte a timestamp
	tick = time(NULL);
	
	//prepare {A,B,kAB,t}kB
	buffer = realloc(buffer, sizeof(char)*2+key_len+sizeof(time_t));
	memcpy(buffer, (void*)&first, sizeof(char));
	memcpy(buffer+sizeof(char), (void*)&second, sizeof(char));
	memcpy(buffer+(sizeof(char)*2), (void*)key12, key_len);
	memcpy(buffer+(sizeof(char)*2)+key_len, (void*)&tick, sizeof(time_t));

	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);	//context init
	EVP_EncryptInit(ctx, cipher, (unsigned char*)key2, NULL);

	block_size = EVP_CIPHER_block_size(cipher);	
	
	ciphertext_len = sizeof(char)*2+key_len+sizeof(time_t) + block_size;
	ciphertext = (unsigned char*)malloc(ciphertext_len);
	
	ret = encrypt(ctx, buffer, sizeof(char)*2+key_len+sizeof(time_t), ciphertext, &ciphertext_len);
	if (ret == 1)
	{
		printf("Error in encrypting the file...");
		return 1;
	}

	//transmission of the ciphertext
	ret = send_buffer(sk, ciphertext, ciphertext_len);
	if (ret == 1)
	{
		printf("Error in sending the encrypted content..\n");
		return 1;
	}

	
	//prepare {B,kAB,t}kA
	buffer = realloc(buffer, sizeof(char)+key_len+sizeof(time_t));
	memcpy(buffer, (void*)&second, sizeof(char));
	memcpy(buffer+sizeof(char), (void*)key12, key_len);
	memcpy(buffer+sizeof(char)+key_len, (void*)&tick, sizeof(time_t));

	ctx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(ctx);	//context init
	EVP_EncryptInit(ctx, cipher, (unsigned char*)key1, NULL);

	block_size = EVP_CIPHER_block_size(cipher);	
	
	ciphertext_len = sizeof(char)+key_len+sizeof(time_t) + block_size;
	ciphertext = (unsigned char*)realloc(ciphertext, ciphertext_len);
	
	ret = encrypt(ctx, buffer, sizeof(char)+key_len+sizeof(time_t), ciphertext, &ciphertext_len);
	if (ret == 1)
	{
		printf("Error in encrypting the file...");
		return 1;
	}

	//transmission of the ciphertext
	ret = send_buffer(sk, ciphertext, ciphertext_len);
	if (ret == 1)
	{
		printf("Error in sending the encrypted content..\n");
		return 1;
	}
	printf("Request from %c was served successfully...", first);

	return 0;
}

int manage_server(int argc, char*argv[])
{
//controlli sui parametri
	int i;

	if(argc != 2) 
	{
     	 	printf("Port number is not correct!\n ");
      		return -1;
   	}

   	if(atoi(argv[1]) <1024 || atoi(argv[1]) > 65535) 
	{
      		printf("Port number is not valid\n");
      		return -1;
   	}

	FD_ZERO(&master);
	FD_ZERO(&read_fds);

   	srv_port = atoi(argv[1]);
   	printf("\nServer is active on port %d \n", srv_port);

   	memset(&srv_addr, 0, sizeof(srv_addr)); 
   	srv_addr.sin_family = AF_INET; 
   	srv_addr.sin_port = htons(srv_port); 
   	ret = inet_pton(AF_INET, SRV_ADDR, &srv_addr.sin_addr);
   	if(ret <= 0) 
	{
     		printf("Address is not correct\n\n");
      		return -1;
   	}

// creazione del socket
   	sk = socket(AF_INET, SOCK_STREAM, 0);
   	if(sk == -1) 
	{
     	 	printf("Error on socket()\n");
      		return -1;
   	}
    
   	optval = 1;
   	ret = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
   	if(ret == -1) 
	{
      		printf("Error on setsockopt()\n");
      		return -1;
   	}


   	memset(&my_addr, 0, sizeof(my_addr)); 
   	my_addr.sin_family = AF_INET;
   	my_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
   	my_addr.sin_port = htons(srv_port);

   	ret = bind(sk, (SA*)&my_addr, sizeof(my_addr));
   	if(ret == -1)
	{
      		printf("\nError on bind()\n");
      		return -1;
   	}

   	ret = listen(sk, BACKLOG_SIZE);
   	if(ret == -1) 
	{
      		printf("Error on backlog size\n" );
      		return -1;
   	}

  	printf("\nWaiting for a connection...\n");

	FD_SET(sk, &master);
	fd_max = sk;

   	while(1) 
	{
		read_fds = master;      		

		ret = select(fd_max+1, &read_fds, NULL, NULL, NULL);
		if (ret==-1)
		{
			printf("Error on select()\n");
			return -1;
		}

		for (i=0; i<=fd_max; i++)
		{
			if (FD_ISSET(i, &read_fds))
			{
				if (i==sk)
				{
					len = sizeof(cl_addr);
      					cl_sk = accept(sk, (SA*)&cl_addr, &len);

      					if(cl_sk == -1) 
					{
         					printf("\nError on accept().\n");
         					return -1;
      					}
				
					inet_ntop(AF_INET, &cl_addr.sin_addr, cl_paddr, sizeof(cl_paddr));
      					cl_port = ntohs(cl_addr.sin_port);
      					printf("\nConnection established with client %s on port %d...\n",  SRV_ADDR, cl_port);

					FD_SET(cl_sk, &master);
					if (cl_sk>fd_max)
						fd_max = cl_sk;
				}
				else
				{
					ret = send_key(i);
					if (ret == 1)
						printf("Error in ask_key()\n");
					close(i);
					FD_CLR(i, &master);
					printf("\n\n\n\nWaiting for a connection...\n");
				}
			}	
		}
       }
      return 0;
}

int main(int argc, char* argv[]) 
{
	int ret;

	ret=manage_server(argc, argv);
	
	if (ret==-1)
	{
		printf("Error in managing the server...\n");
		return 1;
	}

   	return 0;
}
