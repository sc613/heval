#include "he_utils.h"

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>

#define Val_ptr(p) Val_long((long) (p))
#define Params_val(v) ((Params*) Long_val(v))
#define SKey_val(v) ((SecretKey*) Long_val(v))
#define EKey_val(v) ((CloudKey*) Long_val(v))
#define Ctxt_val(v) ((LweSample*) Long_val(v))
#define Env_val(v) ((Env*) Long_val(v))

value ocaml_param_gen(value unit)
{
    return Val_ptr(param_gen());
}

value ocaml_key_gen(value params)
{
    return Val_ptr(key_gen(Params_val(params)));
}

value ocaml_get_evalkey(value sk)
{
    return Val_ptr(get_evalkey(SKey_val(sk)));
}

value ocaml_delete_key(value sk)
{
    delete_key(SKey_val(sk));

    return Val_unit;
}

value ocaml_delete_params(value params)
{
    delete_params(Params_val(params));

    return Val_unit;
}

value ocaml_enc_val(value ptxt, value sk)
{
    return Val_ptr(enc_val(Int_val(ptxt), SKey_val(sk)));
}

value ocaml_enc_id(value ptxt, value sk)
{
    return Val_ptr(enc_id(Int_val(ptxt), SKey_val(sk)));
}

value ocaml_enc_op(value shift, value sk)
{
    return Val_ptr(enc_op(Int_val(shift), SKey_val(sk)));
}

value ocaml_dec_val(value ctxt, value sk)
{
    return Val_int(dec_val(Ctxt_val(ctxt), SKey_val(sk)));
}

value ocaml_create_env(value unit)
{
    return Val_ptr(create_env());
}

value ocaml_bind(value env, value id, value val)
{
    bind(Env_val(env), Ctxt_val(id), Ctxt_val(val));

    return Val_unit;
}

value ocaml_delete_env(value env)
{
    delete_env(Env_val(env));

    return Val_unit;
}

value ocaml_combine_tree(value op, value a, value b, value c, value ck)
{
    return Val_ptr(combine_tree(
        Ctxt_val(op), Ctxt_val(a), Ctxt_val(b), Ctxt_val(c), EKey_val(ck)));
}

value ocaml_combine_leaf(value env, value id, value val, value ck)
{
    return Val_ptr(combine_leaf(
        Env_val(env), Ctxt_val(id), Ctxt_val(val), EKey_val(ck)));
}
