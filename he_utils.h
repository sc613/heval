#pragma once

#include <tfhe/tfhe.h>

typedef TFheGateBootstrappingParameterSet Params;
typedef TFheGateBootstrappingSecretKeySet SecretKey;
typedef const TFheGateBootstrappingCloudKeySet CloudKey;

// Struct encapsulating encrypted environment.
typedef struct Env {
    LweSample **ids;    // array of M-bit ciphertexts
    LweSample **vals;   // array of N-bit ciphertexts
    int ids_nelems;     // number of elements in ids
    int ids_capacity;   // number of slots in memory allocated for ids
    int vals_nelems;    // number of elements in vals
    int vals_capacity;  // number of slots in memory allocated for vals
} Env;

Params *param_gen();

SecretKey *key_gen(const Params *params);

CloudKey *get_evalkey(SecretKey *sk);

void delete_key(SecretKey *sk);

void delete_params(Params *params);

/**
 * Encrypts less significant bits of an integer.
 * 
 * @param ptxt integer to encrypt
 * @param nbits number of bits
 * @param sk secret key
 * @return ciphertext comprised of nbits LweSamples
 */
LweSample *enc(int ptxt, int nbits, SecretKey *sk);

/**
 * Returns an N-bit ciphertext on first N bits of a plaintext representing a value 
 * of a program.
 * 
 * @param ptxt integer to encrypt
 * @param sk secret key
 * @return N-bit ciphertext
 */
LweSample *enc_val(int ptxt, SecretKey *sk);

/**
 * Returns an M-bit ciphertext on first M bits of a plaintext integer representing 
 * an identifier of a program.
 * 
 * @param ptxt integer to encrypt
 * @param sk secret key
 * @return M-bit ciphertext
 */
LweSample *enc_id(int ptxt, SecretKey *sk);

/**
 * Returns a 3-bit one-hot encoded ciphertext given a shift value in {0, 1, 2} 
 * which represents an operation of a program. (0: ADD, 1: NEG, 2: IF)
 * 
 * @param shift shift value
 * @param sk secret key
 * @return 3-bit ciphertext
 */
LweSample *enc_op(int shift, SecretKey *sk);

/**
 * Decrypts a ciphertext comprised of nbits LweSamples. 
 * NOTE: The input ciphertext is deleted afterwards.
 * 
 * @param ctxt ciphertext
 * @param nbits number of bits
 * @param sk secret key
 * @return plaintext integer
 */
int dec(LweSample *ctxt, int nbits, SecretKey *sk);

/**
 * Decrypts an N-bit ciphertext which encodes a value of a program. 
 * NOTE: The input ciphertext is deleted afterwards.
 * 
 * @param ctxt ciphertext
 * @param sk secret key
 * @return plaintext integer
 */
int dec_val(LweSample *ctxt, SecretKey *sk);

/**
 * Computes integer addition of two N-bit ciphertexts homomorphically.
 * 
 * @param a ciphertext
 * @param b ciphertext
 * @param ck evaluation key
 * @return ciphertext
 */
LweSample *add(LweSample *a, LweSample *b, CloudKey *ck);

/**
 * Computes additive inverse of an N-bit ciphertext homomorphically.
 * 
 * @param a ciphertext
 * @param ck evaluation key
 * @return ciphertext
 */
LweSample *change_sign(LweSample *a, CloudKey *ck);

/**
 * Computes (if a = 0 then b else c) homomorphically where a, b, and c are N-bit 
 * ciphertexts.
 * 
 * @param a ciphertext
 * @param b ciphertext
 * @param c ciphertext
 * @param ck evaluation key
 * @return ciphertext
 */
LweSample *if_then_else(LweSample *a, LweSample *b, LweSample *c, CloudKey *ck);

/**
 * Returns a copy of an nelems-bit ciphertext where all of the bits except the most 
 * significant bit are cleared homomorphically.
 * 
 * @param a ciphertext
 * @param nelems number of bits
 * @param ck evaluation key
 * @return ciphertext
 */
LweSample *clear_except_last_set(LweSample *a, int nelems, CloudKey *ck);

/**
 * Returns an nelems-bit ciphertext where i-th bit encodes 1 if a is equal to 
 * array[i] homomorphically and 0 otherwise.
 * 
 * @param a M-bit ciphertext
 * @param array array of nelems M-bit ciphertexts
 * @param nelems number of elements in array
 * @param ck evaluation key
 * @return nelems-bit ciphertext
 */
LweSample *equals_each(LweSample *a, LweSample **array, int nelems, CloudKey *ck);

/**
 * Computes array[i] homomorphically given a one-hot ciphertext which encodes i.
 * 
 * @param one_not nelems-bit ciphertext representing one-hot encoded index
 * @param array array of nelems N-bit ciphertexts
 * @param nelems number of elements in array
 * @param ck evaluation key
 * @return N-bit ciphertext
 */
LweSample *mux(LweSample *one_hot, LweSample **array, int nelems, CloudKey *ck);

/**
 * Appends a ciphertext to an array of nelems ciphertexts.
 * 
 * @param a ciphertext to append
 * @param array array of nelems ciphertexts
 * @param[in, out] nelems pointer to number of elements in array
 * @param[in, out] capacity pointer to number of slots in memory allocated for array
 * @return possibly reallocated input array
 */
LweSample **push(LweSample *a, LweSample **array, int *nelems, int *capacity);

/**
 * Deallocates an array of nelems ciphertexts.
 * 
 * @param array array of ciphertexts to deallocate
 * @param nelems number of elements in array
 * @param nbits number of bits in individual ciphertexts
 */
void delete_ctxt_array(LweSample **array, int nelems, int nbits);

Env *create_env();

/**
 * Appends an encrypted id-value pair to the given environment.
 * 
 * @param env environment
 * @param id M-bit ciphertext which encodes an identifier
 * @param val N-bit ciphertext which encodes a value
 */
void bind(Env *env, LweSample *id, LweSample *val);

/**
 * Returns an encrypted value to which the environment maps the given encrypted 
 * identifier.
 * 
 * @param env environment
 * @param id M-bit ciphertext which encodes an identifier
 * @param ck evaluation key
 * @return N-bit ciphertext which encodes a value
 */
LweSample *lookup(Env *env, LweSample *id, CloudKey *ck);

void delete_env(Env *env);

/**
 * Computes bitwise mux of (a + b), (-a), and (if a = 0 then b else c) given op as 
 * a one-hot encoded selector input, homomorphically. 
 * NOTE: The input ciphertexts are deallocated afterwards.
 * 
 * @param op 3-bit one-hot encoded ciphertext
 * @param a N-bit ciphertext
 * @param b N-bit ciphertext
 * @param c N-bit ciphertext
 * @param ck evaluation key
 * @return N-bit ciphertext
 */
LweSample *combine_tree(
    LweSample *op, LweSample *a, LweSample *b, LweSample *c, CloudKey *ck);

/**
 * Computes bitwise OR of env(id) and val homomorphically. 
 * NOTE: The input ciphertexts are deallocated afterwards.
 * 
 * @param env environment
 * @param id M-bit ciphertext which encodes an identifier
 * @param val N-bit ciphertext which encodes a value
 * @param ck evaluation key
 * @return N-bit ciphertext
 */
LweSample *combine_leaf(Env *env, LweSample *id, LweSample *val, CloudKey *ck);
