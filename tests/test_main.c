#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../jsean.c" // include implementation for simplicity

void test_encryption() {
    JSean jsean;
    SchemaField schema[] = {};
    initialize(&jsean, schema, 0);

    const char *plaintext = "HelloWorld";
    unsigned char ciphertext[128];
    unsigned char tag[AES_TAG_SIZE];
    unsigned char iv[AES_IV_SIZE];
    RAND_bytes(iv, AES_IV_SIZE);
    int cipher_len = encrypt_field((const unsigned char *)plaintext,
                                   strlen(plaintext),
                                   ciphertext,
                                   tag,
                                   iv,
                                   &jsean);
    unsigned char decrypted[128];
    int plain_len = decrypt_field(ciphertext, cipher_len, tag, decrypted, iv, &jsean);
    assert(plain_len >= 0);
    decrypted[plain_len] = '\0';
    assert(strcmp((char *)decrypted, plaintext) == 0);
    printf("test_encryption passed\n");
}

void test_permission() {
    SchemaField schema[] = {
        {"confidential", TYPE_STRING, 0, 0, {}, {"admin"}, 0, 1, 1}
    };
    JSean jsean;
    initialize(&jsean, schema, 1);

    int count_before = jsean.data_count;
    store_data_field(&jsean, "confidential", "secret", "user", "editor");
    assert(jsean.data_count == count_before); // should not store

    store_data_field(&jsean, "confidential", "secret", "admin", "admin");
    assert(jsean.data_count == count_before + 1); // stored

    char output[100] = "unchanged";
    retrieve_data_field(&jsean, "confidential", output, sizeof(output), "editor");
    assert(strcmp(output, "unchanged") == 0); // permission denied

    printf("test_permission passed\n");
}

int main() {
    test_encryption();
    test_permission();
    printf("All tests passed\n");
    return 0;
}

