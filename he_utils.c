#include "he_utils.h"
#include <stdlib.h>

// number of bits encoding a value of a program
#define N 16

// number of bits encoding an identifier
#define M 4

static LweSample *new_ctxt_bit(const Params *params)
{
    return new_gate_bootstrapping_ciphertext(params);
}

static LweSample *new_ctxt(int nbits, const Params *params)
{
    return new_gate_bootstrapping_ciphertext_array(nbits, params);
}

static void delete_ctxt_bit(LweSample *ctxt)
{
    delete_gate_bootstrapping_ciphertext(ctxt);
}

static void delete_ctxt(int nbits, LweSample *ctxt)
{
    delete_gate_bootstrapping_ciphertext_array(nbits, ctxt);
}

Params *param_gen()
{
    const int minimum_lambda = 110;
    return new_default_gate_bootstrapping_parameters(minimum_lambda);
}

SecretKey *key_gen(const Params *params)
{
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed, 3);
    return new_random_gate_bootstrapping_secret_keyset(params);
}

CloudKey *get_evalkey(SecretKey *sk)
{
    return (CloudKey*) &sk->cloud;
}

void delete_key(SecretKey *sk)
{
    delete_gate_bootstrapping_secret_keyset(sk);
}

void delete_params(Params *params)
{
    delete_gate_bootstrapping_parameters(params);
}

LweSample *enc(int ptxt, int nbits, SecretKey *sk)
{
    LweSample *ctxt = new_ctxt(nbits, sk->params);
    for (int i = 0; i < nbits; i++) {
        bootsSymEncrypt(&ctxt[i], (ptxt >> i) & 1, sk);
    }

    return ctxt;
}

LweSample *enc_val(int ptxt, SecretKey *sk)
{
    return enc(ptxt, N, sk);
}

LweSample *enc_id(int ptxt, SecretKey *sk)
{
    return enc(ptxt, M, sk);
}

LweSample *enc_op(int shift, SecretKey *sk)
{
    return enc(1 << shift, 3, sk);
}

int dec(LweSample *ctxt, int nbits, SecretKey *sk)
{
    int ptxt = 0;
    for (int i = 0; i < nbits; i++) {
        ptxt |= bootsSymDecrypt(&ctxt[i], sk) << i;
    }

    delete_ctxt(nbits, ctxt);

    return ptxt;
}

int dec_val(LweSample *ctxt, SecretKey *sk)
{
    return dec(ctxt, N, sk);
}

LweSample *add(LweSample *a, LweSample *b, CloudKey *ck)
{
    LweSample *res = new_ctxt(N, ck->params);
    LweSample *c_in = new_ctxt_bit(ck->params);
    LweSample *c_out = new_ctxt_bit(ck->params);
    LweSample *tmp = new_ctxt(3, ck->params);

    bootsCONSTANT(c_in, 0, ck);

    // ripple-carry adder
    for (int i = 0; i < N; i++) {
        // c_out = (a AND b) OR (c_in AND (a XOR b))
        bootsXOR(&tmp[0], &a[i], &b[i], ck);
        bootsAND(&tmp[1], c_in, &tmp[0], ck);
        bootsAND(&tmp[2], &a[i], &b[i], ck);
        bootsOR(c_out, &tmp[1], &tmp[2], ck);

        // s = a XOR b XOR c_in
        bootsXOR(&res[i], &tmp[0], c_in, ck);

        bootsCOPY(c_in, c_out, ck);
    }

    delete_ctxt_bit(c_in);
    delete_ctxt_bit(c_out);
    delete_ctxt(3, tmp);

    return res;
}

LweSample *change_sign(LweSample *a, CloudKey *ck)
{
    LweSample *res = new_ctxt(N, ck->params);
    LweSample *c_in = new_ctxt_bit(ck->params);
    LweSample *c_out = new_ctxt_bit(ck->params);

    bootsCONSTANT(c_in, 0, ck);

    for (int i = 0; i < N; i++) {
        // -a = ~(a + (-1))
        bootsOR(c_out, &a[i], c_in, ck);
        bootsXOR(&res[i], &a[i], c_in, ck);

        bootsCOPY(c_in, c_out, ck);
    }
    
    delete_ctxt_bit(c_in);
    delete_ctxt_bit(c_out);

    return res;
}

LweSample *if_then_else(LweSample *a, LweSample *b, LweSample *c, CloudKey *ck)
{
    LweSample *res = new_ctxt(N, ck->params);
    LweSample *flag = new_ctxt_bit(ck->params);
    LweSample *tmp = new_ctxt_bit(ck->params);

    bootsCONSTANT(flag, 0, ck);
    for (int i = 0; i < N; i++) {
        // flag |= a[i]
        bootsOR(tmp, flag, &a[i], ck);
        bootsCOPY(flag, tmp, ck);
    }

    for (int i = 0; i < N; i++) {
        bootsMUX(&res[i], flag, &b[i], &c[i], ck);
    }

    delete_ctxt_bit(flag);
    delete_ctxt_bit(tmp);

    return res;
}

LweSample *clear_except_last_set(LweSample *a, int nelems, CloudKey *ck)
{
    LweSample *res = new_ctxt(nelems, ck->params);
    LweSample *tmp = new_ctxt(3, ck->params);

    bootsCOPY(&res[nelems - 1], &a[nelems - 1], ck);
    bootsCONSTANT(&tmp[0], 1, ck);

    for (int i = nelems - 2; i >= 0; i--) {
        // res[i] = (tmp[0] & ~a[i + 1]) & a[i]
        bootsNOT(&tmp[1], &a[i + 1], ck);
        bootsAND(&tmp[2], &tmp[1], &tmp[0], ck);
        bootsAND(&res[i], &tmp[2], &a[i], ck);

        bootsCOPY(&tmp[0], &tmp[2], ck);
    }

    delete_ctxt(3, tmp);

    return res;
}

LweSample *equals_each(LweSample *a, LweSample **array, int nelems, CloudKey *ck)
{
    LweSample *res = new_ctxt(nelems, ck->params);
    LweSample *tmp = new_ctxt(2, ck->params);

    for (int i = 0; i < nelems; i++) {
        bootsCONSTANT(&res[i], 1, ck);
        for (int j = 0; j < M; j++) {
            // res[i] &= a[j] == array[i][j]
            bootsXNOR(&tmp[0], &a[j], &array[i][j], ck);
            bootsAND(&tmp[1], &tmp[0], &res[i], ck);
            bootsCOPY(&res[i], &tmp[1], ck);
        }
    }

    delete_ctxt(2, tmp);

    return res;   
}

LweSample *mux(LweSample *one_hot, LweSample **array, int nelems, CloudKey *ck)
{
    LweSample *res = new_ctxt(N, ck->params);
    LweSample *tmp = new_ctxt(2, ck->params);

    for (int j = 0; j < N; j++) {
        bootsCONSTANT(&res[j], 0, ck);
    }

    for (int i = 0; i < nelems; i++) {
        for (int j = 0; j < N; j++) {
            // res[j] |= one_hot[i] & array[i][j]
            bootsAND(&tmp[0], &one_hot[i], &array[i][j], ck);
            bootsOR(&tmp[1], &tmp[0], &res[j], ck);
            bootsCOPY(&res[j], &tmp[1], ck);
        }
    }

    delete_ctxt(2, tmp);

    return res;
}

LweSample **push(LweSample *a, LweSample **array, int *nelems, int *capacity)
{
    if (*nelems >= *capacity) {
        *capacity = 2 * (*capacity) + 1;    // amortize realloc
        array = realloc(array, (*capacity) * sizeof(LweSample*));

        if (array == NULL) {
            perror("push");
            exit(EXIT_FAILURE);
        }
    }

    array[(*nelems)++] = a;

    return array;
}

void delete_ctxt_array(LweSample **array, int nelems, int nbits)
{
    for (int i = 0; i < nelems; i++) {
        delete_ctxt(nbits, array[i]);
    }

    free(array);
}

Env *create_env()
{
    Env *env = malloc(sizeof(Env));
    if (env == NULL) {
        perror("create_env");
        exit(EXIT_FAILURE);
    }

    env->ids = NULL;    // realloc might fail if not NULL
    env->vals = NULL;
    env->ids_nelems = 0;
    env->ids_capacity = 0;
    env->vals_nelems = 0;
    env->vals_capacity = 0;

    return env;
}

void bind(Env *env, LweSample *id, LweSample *val)
{
    env->ids = push(id, env->ids, &env->ids_nelems, &env->ids_capacity);
    env->vals = push(val, env->vals, &env->vals_nelems, &env->vals_capacity);
}

LweSample *lookup(Env *env, LweSample *id, CloudKey *ck)
{
    int nelems = env->ids_nelems;

    if (nelems == 0) {
        LweSample *empty = new_ctxt(N, ck->params);
        bootsCONSTANT(empty, 0, ck);
        return empty;
    }

    LweSample *all = equals_each(id, env->ids, nelems, ck);
    LweSample *latest = clear_except_last_set(all, nelems, ck);
    LweSample *res = mux(latest, env->vals, nelems, ck);

    delete_ctxt(nelems, all);
    delete_ctxt(nelems, latest);

    return res;
}

void delete_env(Env *env)
{
    delete_ctxt_array(env->ids, env->ids_nelems, M);
    delete_ctxt_array(env->vals, env->vals_nelems, N);
    free(env);
}

LweSample *combine_tree(
    LweSample *op, LweSample *a, LweSample *b, LweSample *c, CloudKey *ck)
{
    LweSample *v0 = add(a, b, ck);
    LweSample *v1 = change_sign(a, ck);
    LweSample *v2 = if_then_else(a, b, c, ck);

    LweSample **array = malloc(sizeof(LweSample*) * 3);
    if (array == NULL) {
        perror("combine");
        exit(EXIT_FAILURE);
    }

    array[0] = v0;
    array[1] = v1;
    array[2] = v2;

    LweSample *res = mux(op, array, 3, ck);

    delete_ctxt(3, op);
    delete_ctxt(N, a);
    delete_ctxt(N, b);
    delete_ctxt(N, c);
    delete_ctxt(N, v0);
    delete_ctxt(N, v1);
    delete_ctxt(N, v2);
    free(array);

    return res;
}

LweSample *combine_leaf(Env *env, LweSample *id, LweSample *val, CloudKey *ck)
{
    LweSample *tmp = lookup(env, id, ck);
    LweSample *res = new_ctxt(N, ck->params);

    for (int i = 0; i < N; i++) {
        bootsOR(&res[i], &tmp[i], &val[i], ck);
    }

    delete_ctxt(M, id);
    delete_ctxt(N, val);
    delete_ctxt(N, tmp);

    return res;
}
