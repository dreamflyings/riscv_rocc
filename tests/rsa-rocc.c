//see LICENSE for license
// The following is a RISC-V program to test the functionality of the
// rsa RoCC accelerator.
// Compile with riscv-unknown-elf-gcc rsa-rocc.c
// Run with spike --extension=rsa pk a.out

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "rsa.h"
#include <stdint.h>

typedef struct uint128 {
  uint64_t hi;
  uint64_t lo;
} uint128;

//Stolen from: https://stackoverflow.com/questions/19738919/gcd-function-for-c/45434118
int gcd(int a, int b)
{
    int temp;
    while (b != 0)
    {
        temp = a % b;
        a = b;
        b = temp;
    }
    return a;
}

//Stolen from: https://stackoverflow.com/questions/27695656/c-pseudo-rsa-solving-for-d-decryption-key-quickly-with-large-numbers
uint64_t extended_gcd(uint64_t a, uint64_t b)
{
    uint64_t x = 0, lastx = 1, y = 1, lasty = 0, temp, quotient;
    while(b != 0)
    {
        temp = b;
        quotient = a / b;
        b = a % b;
        a = temp;
        temp = x;
        x = lastx - quotient * x;
        lastx = temp;
        temp = y;
        y = lasty - quotient * y;
        lasty = temp;
   }
   return lasty;
}


int main() {
/* Private-Key: (128 bit)                                                                                                                                         */
/* modulus: */
/*    00:e0:37:d3:5a:8b:16:0e:b7:f1:19:19:bf:ef:44: */
/*    09:17 */
/* publicExponent: 65537 (0x10001) */
/* privateExponent: */
/*    00:ca:b1:0c:ca:a4:43:7b:67:11:c9:77:a2:77:fe: */
/*    00:a1 */
/* prime1: 18125493163625818823 (0xfb8aafffd4b02ac7) */
/* prime2: 16442969659062640433 (0xe43129c94cf45f31) */
/* exponent1: 5189261458857000451 (0x4803f5cd8dcbfe03) */
/* exponent2: 12850891953204883393 (0xb2578a24fdb3efc1) */
/* coefficient: 10155582946292377246 (0x8cefe0e210c5a69e) */

    //DO NOT MODIFY
    //uint128 modulus = {0xe037d35a8b160eb7LL,  0xf11919bfef440917LL};
    //uint128 privateExp = {0x00cab10ccaa4437b67LL,  0x11c977a277fe00a1LL};
    //uint64_t pubExp = 65537;
    const char plaintext[] = "Hello !";
    //uint128 ciphertext;
    //uint128 decrypted;
    //END DO NOT MODIFY

    uint64_t prime1 = 7103;
    uint64_t prime2 = 8821;
    uint64_t modulus = prime1 * prime2;
    uint64_t totient = (prime1 - 1) * (prime2 - 1);
    uint64_t pubExp = 65537;

    assert(gcd(pubExp, prime1-1) == 1);
    assert(gcd(pubExp, prime2-1) == 1);

    uint64_t priExp;
    int64_t tempPriExp = extended_gcd(totient, pubExp);
    if(tempPriExp < 0)  priExp = tempPriExp + totient;  //Ensure priExp is positive
    else priExp = tempPriExp;

    int text_size = sizeof(plaintext);
    uint64_t ciphertext[text_size];
    uint64_t decrypted;

    printf("prime1:  %ld \n", prime1);
    printf("prime2:  %ld \n", prime2);
    printf("modulus: %ld \n", modulus);
    printf("totient: %ld \n", totient);
    printf("pubExp:  %ld \n", pubExp);
    printf("priExp:  %ld \n\n", priExp);

    int dummy_result;

    uint128 mymod = {0xe037d35a8b160eb7LL, 0xf11919bfef440917};

    uint64_t initCycle, duration;
    initCycle = rdcycle();
    asm volatile ("fence"); //NOTE that fences are only needed if your accelerator accesses memory

    /* YOUR CODE HERE: Invoke your RSA acclerator, write the encrypted output of plaintext to ciphertext */
    //Send publicExp and modulus
    ROCC_INSTRUCTION(0, dummy_result, &pubExp, &modulus, 0);

    //Send plaintext and text size
    ROCC_INSTRUCTION(0, dummy_result, &plaintext, sizeof(plaintext), 1);

    //Send address for ciphertext results
    ROCC_INSTRUCTION(0, dummy_result, &ciphertext, sizeof(plaintext), 2);
    asm volatile ("fence");

    //DO NOT MODIFY
    duration = rdcycle() - initCycle;
    printf("RSA Encryption took %llu cycles!\n", duration);
    initCycle = rdcycle();
    //END DO NOT MODIFY


    /* YOUR CODE HERE: Invoke your RSA acclerator, write the decrypted output of ciphertext to decrypted */
    //Send privateExp and modulus
    ROCC_INSTRUCTION(0, dummy_result, &priExp, &modulus, 3);

    //Send ciphertext and text size
    ROCC_INSTRUCTION(0, dummy_result, &ciphertext, sizeof(plaintext), 4);

    //Send address for decrypted results
    ROCC_INSTRUCTION(0, dummy_result, &decrypted, sizeof(plaintext), 5);
    asm volatile ("fence");

    //DO NOT MODIFY
    duration = rdcycle() - initCycle;
    printf("RSA Decryption took %llu cycles!\n", duration);

    char *decrypted_text = (char*)&decrypted;
    printf("decrypted=%s\n", decrypted_text);
    assert(strcmp(plaintext, decrypted_text) == 0);
}
