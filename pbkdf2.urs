(* pkcs5_pbkdf2_hmac_sha1 performs a secure password hash
 * the parameters are
 *  output length : int
 *  hashing iterations to perform (more iterations makes it harder to crack) : int
 *  password to hash : string
 *  salt : string
 * the return value is a blob which you can store into SQL and compare for equality using eq
 *)
val pkcs5_pbkdf2_hmac_sha1 : int -> int -> string -> string -> option blob

(* the eq function use a timing safe equality test *)
val eq : blob -> blob -> bool

val test_vector : int -> blob
