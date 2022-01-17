#include "gm_crypto.h"

int main(int argc, char** argv)
{
        pubkey_t* pbkey = malloc(sizeof(pubkey_t));
        privkey_t* prkey = malloc(sizeof(privkey_t));
        
        // Generate public and private key (we assume that only one party is transmitting information)
        gen_keys(pbkey, prkey);        

        // unsigned short message = 1;         

        // mpz_t *cc = enc_bit(NULL, message, pbkey);
        // gmp_printf("The cyphertext is : %Zd\n", *cc);

        // unsigned short pp;

        // dec_bit(&pp, cc, prkey);

        // printf("Decrypted plaintext is : %d\n", pp);



        unsigned short msg[5] = {1,0,1,0,0};        
       
        mpz_t **cc = enc_bitstream(NULL, msg, 5, pbkey);
        
        unsigned short ** decmsg = dec_bitstream(NULL, cc, 5, prkey);

        for (int i=0; i<5; i++)
        {
                free(*(cc+i));
                free(*(decmsg+i));
        }
        free(decmsg);        
        free(cc);
        free(pbkey);
        free(prkey);
        
        return 0;
}