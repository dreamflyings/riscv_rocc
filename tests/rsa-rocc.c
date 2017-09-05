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

    unsigned __int128 modulus = (0xe037d35a8b160eb7LL << 32) | 0xf11919bfef440917LL;
    unsigned __int128 privateExp = (0x00cab10ccaa4437b67LL << 32) |  0x11c977a277fe00a1LL;
    unsigned __int128 pubExp = 65537;
    const char plaintext[] = "Hello !";
    unsigned __int128 ciphertext;
    unsigned __int128 decrypted;
    int dummy_result;

    /* asm volatile ("fence"); */
    /* YOUR CODE HERE: Invoke your RSA acclerator, write the encrypted output of plaintext to ciphertext */
    /* asm volatile ("fence"); */
    /* YOUR CODE HERE: Invoke your RSA acclerator, write the decrypted output of ciphertext to decrypted */
    /* asm volatile ("fence"); */


    char *decrypted_text = (char*)&decrypted;
    printf("decrypted=%s\n", decrypted_text);
    assert(strcmp(plaintext, decrypted_text) == 0);
}
