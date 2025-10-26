void aes_init(void);
void aes128_expand_key(uint8_t *key, uint32_t *w, uint32_t *v);
void aes128_encrypt_block(uint32_t *w, uint8_t *in, uint8_t *out);
void aes128_decrypt_block(uint32_t *w, uint8_t *in, uint8_t *out);
void aes256_expand_key(uint8_t *key, uint32_t *w, uint32_t *v);
void aes256_encrypt_block(uint32_t *w, uint8_t *in, uint8_t *out);
void aes256_decrypt_block(uint32_t *v, uint8_t *in, uint8_t *out);
