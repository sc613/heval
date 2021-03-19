(* plain expression *)
type exp =
  | NUM of int
  | VAR of string
  | ADD of exp * exp
  | NEG of exp
  | IF of exp * exp * exp
  | LET of string * exp * exp

(* encrypted expression *)
type eexp =
  | TREE of He.c_op * eexp * eexp * eexp
  | LEAF of He.c_id * He.c_val
  | BIND of He.c_id * eexp * eexp

(* plain evaluation *)
let rec eval env e =
  match e with
  | NUM n -> n
  | VAR x ->
    List.assoc x env
  | ADD (e1, e2) ->
    (eval env e1) + (eval env e2)
  | NEG e ->
    -(eval env e)
  | IF (e1, e2, e3) ->
    if eval env e1 != 0 then
      eval env e2
    else
      eval env e3
  | LET (x, e1, e2) ->
    let n = eval env e1 in
    eval ((x, n) :: env) e2

(* hash table to maintain a set of distinct identifiers *)
let tbl = Hashtbl.create 16

(* encryption of identifiers *)
let enc_var x sk = 
  let cnt = Hashtbl.length tbl in
  match Hashtbl.find_opt tbl x with
  | Some n ->
    He.enc_id n sk
  | None ->
    Hashtbl.add tbl x cnt;
    He.enc_id (cnt + 1) sk

let get_dummy sk = LEAF (He.enc_id 0 sk, He.enc_val 0 sk)

(* encryption of plain expressions *)
let rec enc_exp e sk =
  match e with
  | NUM n ->
    LEAF (He.enc_id 0 sk, He.enc_val n sk)
  | VAR x ->
    LEAF (enc_var x sk, He.enc_val 0 sk)
  | ADD (e1, e2) ->
    let ee1 = enc_exp e1 sk in
    let ee2 = enc_exp e2 sk in
    let ee3 = get_dummy sk in
    TREE (He.enc_op 0 sk, ee1, ee2, ee3)
  | NEG e ->
    let ee1 = enc_exp e sk in
    let ee2 = get_dummy sk in
    let ee3 = get_dummy sk in
    TREE (He.enc_op 1 sk, ee1, ee2, ee3)
  | IF (e1, e2, e3) ->
    let ee1 = enc_exp e1 sk in
    let ee2 = enc_exp e2 sk in
    let ee3 = enc_exp e3 sk in
    TREE (He.enc_op 2 sk, ee1, ee2, ee3)
  | LET (x, e1, e2) ->
    let ee1 = enc_exp e1 sk in
    let ee2 = enc_exp e2 sk in
    BIND (enc_var x sk, ee1, ee2)
  
(* encryption of plain environments *)
let enc_env env sk =
  let eenv = He.create_env () in
  let () = He.bind eenv (He.enc_id 0 sk) (He.enc_val 0 sk) in
  let () =
    let enc_and_bind (x, n) =
      let ex = enc_var x sk in
      let en = He.enc_val n sk in
      He.bind eenv ex en
    in
    List.iter enc_and_bind (List.rev env)
  in
  eenv

(* homomorphic evaluation of encrypted expressions *)
let rec eeval eenv ee ek =
  match ee with
  | TREE (eop, ee1, ee2, ee3) ->
    let en1 = eeval eenv ee1 ek in
    let en2 = eeval eenv ee2 ek in
    let en3 = eeval eenv ee3 ek in
    He.combine_tree eop en1 en2 en3 ek
  | LEAF (ex, en) ->
    He.combine_leaf eenv ex en ek
  | BIND (ex, ee1, ee2) ->
    let en = eeval eenv ee1 ek in
    let () = He.bind eenv ex en in
    eeval eenv ee2 ek
