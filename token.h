#ifndef TOKEN_H__
#define TOKEN_H__

/* token API */

/* basic token operations */
#define TO_INFO     1  /* YES|SUPERCEDED\n<user>\n<auth>\n */
#define TO_REPLACE  2  /* <token>\n<user>\n<auth>\n */
#define TO_REVOKE   3  /* OK */

/* key operations */
#define TO_GET_KEY  5  /* <key> */
#define TO_GEN_KEY  6  /* <key> */

const char *token_op(const char *token, const char *realm, int op);
int         auth_module(const char *realm, const char *user, const char *pwd, const char *module);
int         gen_token(char *token, int max_len);
const char *store_token(const char *token, const char *realm, const char *user, const char *module);

#endif
