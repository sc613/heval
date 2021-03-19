type params
type key_s  (* secret key *)
type key_e  (* evaluation key*)
type c_val  (* encrypted value*)
type c_id   (* encrypted identifier *)
type c_op   (* encrypted opcode *)
type c_env  (* encrypted environment*)

external param_gen : unit -> params = "ocaml_param_gen"
external key_gen : params -> key_s = "ocaml_key_gen"
external get_evalkey : key_s -> key_e = "ocaml_get_evalkey"
external delete_key : key_s -> unit = "ocaml_delete_key"
external delete_params : params -> unit = "ocaml_delete_params"
external enc_val : int -> key_s -> c_val = "ocaml_enc_val"
external enc_id : int -> key_s -> c_id = "ocaml_enc_id"
external enc_op : int -> key_s -> c_op = "ocaml_enc_op"
external dec_val : c_val -> key_s -> int = "ocaml_dec_val"
external create_env : unit -> c_env = "ocaml_create_env"
external bind : c_env -> c_id -> c_val -> unit = "ocaml_bind"
external delete_env : c_env -> unit = "ocaml_delete_env"
external combine_tree : c_op -> c_val -> c_val -> c_val -> key_e -> c_val
  = "ocaml_combine_tree"
external combine_leaf : c_env -> c_id -> c_val -> key_e -> c_val
  = "ocaml_combine_leaf"
