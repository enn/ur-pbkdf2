#include <urweb.h>

uw_Basis_blob *uw_Pbkdf2_pkcs5_pbkdf2_hmac_sha1(uw_context ctx, uw_Basis_int size, uw_Basis_int iter, uw_Basis_string str, uw_Basis_string salt);
uw_Basis_bool uw_Pbkdf2_eq(uw_context ctx, uw_Basis_blob b1, uw_Basis_blob b2);
uw_Basis_blob uw_Pbkdf2_test_vector(uw_context ctx, uw_Basis_int i);
