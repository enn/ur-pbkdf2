fun hash s = case Pbkdf2.pkcs5_pbkdf2_hmac_sha1 32 5 s "salt" of
                 None => error <xml/>
               | Some b => returnBlob b (blessMime "binary")

fun test_vector i =
    case (case i of
              0 => Pbkdf2.pkcs5_pbkdf2_hmac_sha1 20 1 "password" "salt"
            | 1 => Pbkdf2.pkcs5_pbkdf2_hmac_sha1 20 2 "password" "salt"
            | 2 => Pbkdf2.pkcs5_pbkdf2_hmac_sha1 20 4096 "password" "salt"
            | 3 => Pbkdf2.pkcs5_pbkdf2_hmac_sha1 20 16777216 "password" "salt"
            | 4 => Pbkdf2.pkcs5_pbkdf2_hmac_sha1 25 4096 "passwordPASSWORDpassword" "saltSALTsaltSALTsaltSALTsaltSALTsalt"
            | _ => None) of
        Some b => b
      | None => error <xml/>

fun perform_test i =
    if Pbkdf2.eq (test_vector i) (Pbkdf2.test_vector i) then
        <xml>test {[i]} passed</xml>
    else
        <xml>test {[i]} failed</xml>

fun main () = return <xml>
  <body>
    <h1>PBKDF2 Test Vectors:</h1>
    <ul>
      <li>{perform_test 0}</li>
      <li>{perform_test 1}</li>
      <li>{perform_test 2}</li>
      <li>{perform_test 3}</li>
      <li>{perform_test 4}</li>
    </ul>
    <br/>
    <a link={hash "a string"}>hash a string</a>
  </body>
</xml>
