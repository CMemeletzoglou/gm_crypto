#include "gm_crypto.h"


void gen_keys(pubkey_t* pbkey, privkey_t* prkey)
{
        mpz_t p, q, N;
        mpz_inits(p, q, N, NULL);
        unsigned long int seed;

        gmp_randstate_t rndstate;
        gmp_randinit_default(rndstate);

        arc4random_buf(&seed, sizeof(seed)); // generate high quality random number to use as PRNG seed (Linux only function)
        
        gmp_randseed_ui(rndstate, seed);
        mpz_urandomb(p, rndstate, PRIME_LENGTH); // random integer of 512 bits
        if(mpz_probab_prime_p(p, 50) == 0) // if p is definitely not prime, then find its closest prime, and choose that as the new p
                mpz_nextprime(p, p);

        mpz_urandomb(q, rndstate, PRIME_LENGTH);
        if(mpz_probab_prime_p(q, 50) == 0) //similarly, for q
                mpz_nextprime(q, q);

        mpz_mul(N, p, q); // multiply the two prime numbers to form the modulus N

        // find quadratic nonresidue mod N, a
        mpz_t a, pm1, p_exp, p_res, qm1, q_exp, q_res;
        mpz_inits(a, pm1, p_exp, p_res, qm1, q_exp, q_res, NULL);

        mpz_sub_ui(pm1, p, 1); // compute p-1
        mpz_sub_ui(qm1, q, 1); // compute q-1

        mpz_div_ui(p_exp, pm1, 2); // compute (p-1)/2
        mpz_div_ui(q_exp, qm1, 2); // compute (q-1)/2

        /* pick a random integer a, of 512 bits, compute p_res = a^(p_exp) (mod p) and q_res = a^(q_exp) (mod q).
         * If p_res and q_res are equal to 1, then a is a quadratic residue mod p and mod q, therefore it will be
         * a quadratic residue mod (p*q) = (mod N). We need a to be a quadratic **nonresidue** (mod N), so keep picking
         * random integers, until both p_res and q_res are equal to zero.
         */
        do
        {
                mpz_urandomb(a, rndstate, PRIME_LENGTH);
                mpz_powm(p_res, a, p_exp, p);
                mpz_powm(q_res, a, q_exp, q);
                
        } while (mpz_cmp_ui(p_res, 1) == 0 || mpz_cmp_ui(q_res, 1) == 0);        
        
        //Store public key, (a,N)
       mpz_set(pbkey->N, N);
       mpz_set(pbkey->a, a);

        //Store private key , (p,q)
        mpz_set(prkey->p, p);
        mpz_set(prkey->q, q);      

        mpz_clears(p, q, N, a, pm1, p_exp, p_res, qm1, q_exp, q_res, NULL);
        gmp_randclear(rndstate);
}

/* Encrypt a single bit */
mpz_t *enc_bit(mpz_t *cyphertext, unsigned short plaintext, pubkey_t *pbkey)
{
        if(!cyphertext)
        {
                cyphertext = malloc(sizeof(mpz_t));
                mpz_init(*cyphertext);
        }

        gmp_randstate_t rndstate;
        gmp_randinit_default(rndstate);

        unsigned long int seed;
        arc4random_buf(&seed, sizeof(seed));
        gmp_randseed_ui(rndstate, seed);

        mpz_t r;        
        mpz_init(r);
                
        while(1) // while loop just in case the random number is equal to zero, which is unwanted, since we need 1 < r < N
        {
                mpz_urandomm(r, rndstate, pbkey->N); // Generate the random element                
                if( mpz_cmp_ui(r, 0) > 0)
                        break;
        }
        
        //compute cyphertext
        if(plaintext == 0)
                mpz_powm_ui(*cyphertext, r, 2, pbkey->N);
        else if(plaintext == 1)
        {
                mpz_t ar_squared;
                mpz_init(ar_squared);
                mpz_mul(r, r, r); // r <- r^2
                mpz_mul(ar_squared, r, pbkey->a);
                mpz_mod(*cyphertext, ar_squared, pbkey->N);
                mpz_clear(ar_squared);
        }    

        gmp_randclear(rndstate);
        mpz_clear(r);        
        return cyphertext;
}

/* Encrypt multiple bits at once (i.e. a bitstream)  */
mpz_t **enc_bitstream(mpz_t **cyphertext, unsigned short *plaintext, unsigned short msg_size, pubkey_t *pbkey) // the message consists of **msg_size** bits
{
        if(!cyphertext)
        {
                cyphertext = malloc(msg_size * sizeof(mpz_t*));
                for(int i=0; i<msg_size; i++)
                {
                        *(cyphertext + i) = malloc(sizeof(mpz_t));
                        mpz_init(**(cyphertext+i));
                }
        }
        
        for(int i=0; i<msg_size; i++)
                mpz_set(**(cyphertext + i),  *(enc_bit(*(cyphertext+i), *(plaintext+i), pbkey)) );

        return cyphertext;
}

/* Decrypt a single bit */
unsigned short *dec_bit(unsigned short *plaintext, mpz_t *cyphertext, privkey_t *prkey)
{
        if(!plaintext)
                plaintext = malloc(sizeof(unsigned short));
                
        int legendre_res =  mpz_legendre(*cyphertext, prkey->p);
        if( legendre_res == 1)
                *plaintext = 0;
        else if(legendre_res == -1)
                *plaintext = 1;
        
        return plaintext;
}

/* Decrypt multiple bits at once */
unsigned short **dec_bitstream(unsigned short **plaintext, mpz_t **cyphertext, unsigned short msg_size, privkey_t *prkey)
{
        if(!plaintext)
        {
                plaintext = malloc(msg_size * sizeof(unsigned short*));
                for(int i=0; i<msg_size; i++)
                        *(plaintext+i) = malloc(sizeof(unsigned short));                
        }
        
        for(int i=0; i<msg_size; i++)
                dec_bit(*(plaintext+i), *(cyphertext+i), prkey); 

        return plaintext;
}

