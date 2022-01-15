#include <fcntl.h>
#include <stdio.h>
#include <bsd/stdlib.h> //needed for arc4random_buf
#include <unistd.h>
#include <time.h>
#include <gmp.h>





#define PRIME_LENGTH 512

/* The Goldwasser - Micali public key, is the tuple of the modulus N (where N is a composite number, which is the product
 * of two primes, p,q , i.e N=p*q) and the number a, where a is a quadratic nonresidue modulo N, chosen at random, so that 
 * the Legendre symbols (a/p) and (a/q) are both equal to -1, therefore, the Jacobi symbol (a/p*q) = (a/N) is equal to 1
 */
typedef struct pubkey_t
{
        mpz_t N; // the modulus, where N=p*q
        mpz_t a; // the quadratic nonresidue modulo N
}pubkey_s;

/* The Goldwasser - Micali private key, is the tuple of the two prime factors of the composite number N */
typedef struct privkey_t
{
        mpz_t p;
        mpz_t q;
}privkey_s;


void gen_keys(pubkey_s* pbkey, privkey_s* prkey)
{
        mpz_t p, q, N;
        mpz_inits(p, q, N, NULL);
        unsigned long int seed;

        gmp_randstate_t rndstate;
        gmp_randinit_default(rndstate);

        arc4random_buf(&seed, sizeof(seed)); // generate high quality random number to use as PRNG seed
        
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
}




int main(int argc, char** argv)
{
        pubkey_s* pbkey = malloc(sizeof(pubkey_s));
        privkey_s* prkey = malloc(sizeof(privkey_s));
        
        // Generate public key
        gen_keys(pbkey, prkey);

      
        
        return 0;
}