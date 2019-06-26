//see LICENSE for license
#ifndef _RISCV_RSA_ROCC_H
#define _RISCV_RSA_ROCC_H

#include "rocc.h"
#include "mmu.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

class rsa_t : public rocc_t
{
public:
  rsa_t() {};

  const char* name() { return "rsa"; }

  void reset()
  {
  }

  //Find number of base2 values in key (exponent) needed for lookupArray
  int findExpBase2ElemCount(uint64_t exponent)
  {
	int counter = 0;
	for(uint64_t i = 1; i < exponent; i *= 2)
		counter += 1;
	//printf("findExpBase2ElemCount.counter: %d \n", counter);
	return counter;
  }

  //Create a lookup array containing: "all base-2 powers mod modulus of the plaintext char"
  uint64_t* createLookupArray(int num_elems, int plainChar, uint64_t modulus)
  { 
	uint64_t* results = (uint64_t*)malloc(num_elems * sizeof(uint64_t));	
	results[0] = (uint64_t)plainChar % modulus;
	for(int i = 1; i < num_elems; i++)
	{
		results[i] = ((uint64_t)pow(results[i-1], 2)) % modulus;
		//printf("createLookupArray.results[%d]: %ld \n", i, results[i]);
	}

	return results;
  } 
  
  //Create an array containing the binary representation of the key (pub/pri exponent)
  bool* createBinaryExpArray(uint64_t exponent)
  {
	bool* results = (bool*)malloc(64 * sizeof(bool)); //exponent is a 64bit number
	uint64_t mask = 1 << 63;  //Must instantiate as 64bit value for compiler to allocate 64bits
	mask = 1;
	for(int i = 0; i < 64; i++)
	{
		if((exponent & mask) > 0)
			results[i] = 1;
		else
			results[i] = 0;

		//printf("createBinaryExpArray.results[%d]: %d \n", i, results[i]);
		mask = mask << 1;
	}
	return results;
  }

  //Use the lookupArray and binaryExpArray to calculate the cipher value of the plainChar
  uint64_t combineCalculatedValues(uint64_t* lookupArray, int lookupArraySize, bool* binaryKeyArray, uint64_t modulus)
  {
	uint64_t total_coeff = 1 << 63; //Init to a 64bit value
	total_coeff = 1;
	for(int i = 0; i < lookupArraySize; i++)
		if(binaryKeyArray[i] == 1)
		{
			//printf("combineCalculatedValues.lookupArray[%d]: %ld \n", i, lookupArray[i]);
			total_coeff = (total_coeff * lookupArray[i]) % modulus;
		}
	//printf("combineCalculatedValues.total_coeff mod modulus: %ld mod %ld \n", total_coeff, modulus);
	return total_coeff % modulus;
  }

  uint64_t encrypt(char plain, uint64_t pubExp, uint64_t modulus)
  {
//	printf("%c is %d, ", plain, (int)plain);
	int pow_counter = findExpBase2ElemCount(pubExp);
	uint64_t* lookupArray = createLookupArray(pow_counter, plain, modulus);
	bool* binPubExp = createBinaryExpArray(pubExp);
	uint64_t result = combineCalculatedValues(lookupArray, pow_counter, binPubExp, modulus);
//	printf("encrypted: %ld \n", result);
	return result;

  }

  char decrypt(uint64_t cipher, uint64_t priExp, uint64_t modulus)
  {
	int pow_counter = findExpBase2ElemCount(priExp);
	uint64_t* lookupArray = createLookupArray(pow_counter, cipher, modulus);
	bool* binPriExp = createBinaryExpArray(priExp);
	uint64_t charValue = combineCalculatedValues(lookupArray, pow_counter, binPriExp, modulus);
//	printf("charValue: %ld = %c \n", charValue, char(charValue));

	return (char)charValue;
  }


  reg_t custom0(rocc_insn_t insn, reg_t xs1, reg_t xs2)
  {
    switch (insn.funct)
    {
      case 0: //Encrypt; receive pubExp and modulus
        pubExp_reg = xs1;
        pubExp = p->get_mmu()->load_uint64(pubExp_reg);

        mod_reg = xs2;
        modulus = p->get_mmu()->load_uint64(mod_reg);
	
        break;

      case 1: //Encrypt; receive plaintext and text size
        text_size = xs2;
        plaintext = (unsigned char*) malloc(text_size * sizeof(char));
        for(int i = 0; i < text_size; i++)
                plaintext[i] = p->get_mmu()->load_uint8(xs1 + i);

        break;


      case 2: //Encrypt; receive addr for ciphertext and text size and send ciphertext back
        ciphertext_reg = xs1;

	for(int i = 0; i < text_size; i++)
	{
		p->get_mmu()->store_uint64(ciphertext_reg+(i * sizeof(uint64_t)), encrypt(plaintext[i], pubExp, modulus));
		if(plaintext[i] == '\0')
			break;
	}
	free(plaintext);
        break;


      case 3: //Decrypt; receive priExp and modulus
        priExp_reg = xs1;
        priExp = p->get_mmu()->load_uint64(priExp_reg);

        mod_reg = xs2;
        modulus = p->get_mmu()->load_uint64(mod_reg);

	break;


      case 4: //Decrypt; receive ciphertext and text size
	text_size = xs2;
	encrypted = (uint64_t*)malloc(text_size * sizeof(uint64_t));
	
	for(int i = 0; i < text_size; i++)
		encrypted[i] = (uint64_t)p->get_mmu()->load_uint64(xs1 + (i * sizeof(uint64_t)));
	
	break;


      case 5: //Decrypt; receive address for decrypted results and send them back

	for(int i = 0; i < text_size; i++)
		p->get_mmu()->store_uint8(xs1+(i*sizeof(uint8_t)), (uint8_t)decrypt(encrypted[i], priExp, modulus));
	
	free(encrypted);
	break;

      default:
        illegal_instruction();
    }

    return -1; // accelerator currently returns nothing
  }
private:
  reg_t pubExp_reg;
  reg_t priExp_reg;
  reg_t mod_reg;
  unsigned char* plaintext;
  uint64_t* encrypted;
  reg_t ciphertext_reg;
  int text_size;

  uint64_t priExp;
  uint64_t pubExp;
  uint64_t modulus;
};
REGISTER_EXTENSION(rsa, []() { return new rsa_t; })
#endif
