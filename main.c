#include "gm_crypto.h"
#include <string.h>

int main(int argc, char** argv)
{
        pubkey_t* pbkey = malloc(sizeof(pubkey_t));
        privkey_t* prkey = malloc(sizeof(privkey_t));
        
        // Generate public and private key (we assume that only one party is transmitting information)
        gen_keys(pbkey, prkey);        

        printf("Input the binary string to be encrypted :\t");
        char str[1024];
        scanf("%s", str);

        size_t input_len = strlen(str);

        if(input_len == 1)
        {
               unsigned short msg =  strtoul(str, NULL, 2);
               mpz_t *cyphtext = enc_bit(NULL, msg, pbkey);
               unsigned short *ptext = dec_bit(NULL, cyphtext, prkey);
               printf("The decrypted plaintext is : %d\n", *ptext);

               free(cyphtext);
               free(ptext);
        }                
        else if(input_len > 1)
        {
                unsigned short *msg = malloc(input_len * sizeof(unsigned short));
                for(int i=0; i<input_len; i++)
                       *(msg+i) = str[i] - '0';

                mpz_t **cyphtext = enc_bitstream(NULL, msg, input_len, pbkey);
                unsigned short **ptext = dec_bitstream(NULL, cyphtext, input_len, prkey);

                printf("Decrypted: ");
                for(int i=0; i<input_len; i++)
                {
                        printf("%d", **(ptext+i)); 
                        free(*(cyphtext+i));
                        free(*(ptext+i));
                }
                free(msg);  
                free(cyphtext);
                free(ptext);          
        }
        printf("\n");
        return 0;
}