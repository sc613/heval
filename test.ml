open Prog

let env = [("input", 2021)]
let e = 
  LET (
    "x", NUM 314,
    LET (
      "y", NUM 159,
      IF (
        ADD (VAR "input", NEG (NUM 2021)),
        VAR "x",
        VAR "y"
      )
    )
  )

let ans = eval env e

(* makeshift helper function for checking execution times *)
let profile name cmd =
  let t1 = Sys.time () in
  let retval = Lazy.force cmd in
  let t2 = Sys.time () in
  let () = Printf.printf "%s: %f secs" name (t2 -. t1) in
  let () = print_newline () in  (* also flushes stdout *)
  retval

let cmd = lazy (He.param_gen ())
let params = profile "param_gen" cmd

let cmd = lazy (He.key_gen params)
let sk = profile "key_gen" cmd

let cmd = lazy (He.get_evalkey sk)
let ek = profile "get_eval_key" cmd

let cmd = lazy (enc_env env sk)
let eenv = profile "enc_env" cmd

let cmd = lazy (enc_exp e sk)
let ee = profile "enc_exp" cmd

let cmd = lazy (eeval eenv ee ek)
let en = profile "eeval" cmd

let cmd = lazy (He.dec_val en sk)
let n = profile "dec_val" cmd

let cmd = lazy (He.delete_key sk)
let () = profile "delete_key" cmd

let cmd = lazy (He.delete_params params)
let () = profile "delete_params" cmd

(* decoding 16-bit integer *)
let res =
  if n land (1 lsl 15) == 0 then n
  else n - 0x10000

let () = Printf.printf
  "\nresult = %d %s %d = answer\n"
  res
  (if res = ans then "=" else "!=")
  ans
