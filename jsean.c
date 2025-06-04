#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define MAX_FIELDS 10
#define MAX_VERSIONS 20
#define MAX_LOG_LENGTH 100
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16

// Field Types
typedef enum {
    TYPE_INT,
    TYPE_STRING
} FieldType;

// Schema for each field
typedef struct {
    char key[50];
    FieldType type;
    int int_min;
    int int_max;
    char allowed_values[3][50];
    char permission_levels[3][20];  // Allowed permission levels
    int num_allowed_values;
    int num_permission_levels;
    int is_encrypted;
} SchemaField;

// A single data field
typedef struct {
    char key[50];
    unsigned char value[100];
    int value_len;
    unsigned char iv[AES_IV_SIZE];
    unsigned char tag[AES_TAG_SIZE];
    int is_encrypted;
} DataField;

// Types of versions: Snapshot or Delta
typedef enum {
    SNAPSHOT,
    DELTA
} VersionType;

// A version entry (snapshot or delta)
typedef struct {
    VersionType type;
    time_t timestamp;
    DataField changes[MAX_FIELDS];
    int num_changes;
    char action[MAX_LOG_LENGTH];
    char user[50];
    char permission_level[20];
} Version;

// JSean structure
typedef struct {
    DataField data[MAX_FIELDS];
    int data_count;
    Version versions[MAX_VERSIONS];
    int version_count;
    SchemaField schema[MAX_FIELDS];
    int schema_count;
    unsigned char aes_key[AES_KEY_SIZE];
} JSean;

// Helper function for timestamp
time_t current_timestamp() {
    return time(NULL);
}

// Initialize JSean structure with schema and AES key/IV
void initialize(JSean *jsean, SchemaField *schema, int schema_count) {
    jsean->data_count = 0;
    jsean->version_count = 0;
    memcpy(jsean->schema, schema, schema_count * sizeof(SchemaField));
    jsean->schema_count = schema_count;
    if (RAND_bytes(jsean->aes_key, AES_KEY_SIZE) != 1) { // Generate AES key
        fprintf(stderr, "RAND_bytes failed in initialize\n");
        exit(EXIT_FAILURE);
    }
}

// AES-GCM encryption function for field values
int encrypt_field(const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext,
                  unsigned char *tag, const unsigned char *iv, JSean *jsean) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, jsean->aes_key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES-GCM decryption function for field values
int decrypt_field(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *tag,
                  unsigned char *plaintext, const unsigned char *iv, JSean *jsean) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, jsean->aes_key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void *)tag);
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // Decryption failed
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Overwrite sensitive buffers before program exit
void cleanup_jsean(JSean *jsean) {
    OPENSSL_cleanse(jsean->aes_key, AES_KEY_SIZE);

    for (int i = 0; i < jsean->data_count; i++) {
        OPENSSL_cleanse(jsean->data[i].value, sizeof(jsean->data[i].value));
    }
}

// Check if user has permission to access or modify a field
int has_permission(SchemaField *field, const char *permission_level) {
    for (int i = 0; i < field->num_permission_levels; i++) {
        if (strcmp(field->permission_levels[i], permission_level) == 0) {
            return 1;
        }
    }
    return 0;
}

// Store a data field with encryption based on schema and permissions
void store_data_field(JSean *jsean, const char *key, const char *value, const char *user, const char *permission_level) {
    SchemaField *schema_field = NULL;
    for (int i = 0; i < jsean->schema_count; i++) {
        if (strcmp(jsean->schema[i].key, key) == 0) {
            schema_field = &jsean->schema[i];
            break;
        }
    }

    if (!schema_field) {
        printf("Error: No schema found for key '%s'\n", key);
        return;
    }

    // Permission check
    if (!has_permission(schema_field, permission_level)) {
        printf("Permission Error: User '%s' with level '%s' not allowed to modify key '%s'\n", user, permission_level, key);
        return;
    }

    // Validation based on schema
    char validated_value[100];
    strncpy(validated_value, value, sizeof(validated_value) - 1);
    validated_value[sizeof(validated_value) - 1] = '\0';

    if (schema_field->type == TYPE_INT) {
        char *endptr;
        long int_val = strtol(value, &endptr, 10);
        if (*endptr != '\0') {
            printf("Validation Error: Value '%s' for key '%s' is not a valid integer\n", value, key);
            return;
        }
        if (int_val < schema_field->int_min || int_val > schema_field->int_max) {
            printf("Validation Error: Integer value %ld for key '%s' out of range (%d-%d)\n",
                   int_val, key, schema_field->int_min, schema_field->int_max);
            return;
        }
        snprintf(validated_value, sizeof(validated_value), "%ld", int_val);
    } else if (schema_field->type == TYPE_STRING && schema_field->num_allowed_values > 0) {
        int valid = 0;
        for (int i = 0; i < schema_field->num_allowed_values; i++) {
            if (strcmp(schema_field->allowed_values[i], value) == 0) {
                valid = 1;
                break;
            }
        }
        if (!valid) {
            printf("Validation Error: Value '%s' not allowed for key '%s'\n", value, key);
            return;
        }
    }

    int is_encrypted = schema_field->is_encrypted;
    unsigned char encrypted_value[128];
    int encrypted_len = 0;

    if (jsean->data_count >= MAX_FIELDS) {
        printf("Error: Maximum number of fields reached\n");
        return;
    }

    DataField *data_field = &jsean->data[jsean->data_count];

    if (strlen(key) >= sizeof(data_field->key)) {
        printf("Error: Key '%s' exceeds maximum length\n", key);
        return;
    }
    snprintf(data_field->key, sizeof(data_field->key), "%s", key);
    if (is_encrypted) {

        if (RAND_bytes(data_field->iv, AES_IV_SIZE) != 1) {
            fprintf(stderr, "RAND_bytes failed in store_data_field\n");
            exit(EXIT_FAILURE);
        }
        encrypted_len = encrypt_field((unsigned char *)value, strlen(value), encrypted_value,
                                      data_field->tag, data_field->iv, jsean);
        memcpy(data_field->value, encrypted_value, encrypted_len);
        data_field->value_len = encrypted_len;
        data_field->is_encrypted = 1;
        printf("Stored encrypted value for key '%s'\n", key);
    } else {
        strncpy((char *)data_field->value, value, sizeof(data_field->value) - 1);
        data_field->value[sizeof(data_field->value) - 1] = '\0';
        data_field->value_len = strlen((char *)data_field->value);
        data_field->is_encrypted = 0;
        printf("Stored plain value for key '%s'\n", key);
    }


    jsean->data_count++;
}

// Retrieve and decrypt a data field if encrypted, with permission check
void retrieve_data_field(JSean *jsean, const char *key, char *output, size_t output_size, const char *permission_level) {
    SchemaField *schema_field = NULL;
    for (int i = 0; i < jsean->schema_count; i++) {
        if (strcmp(jsean->schema[i].key, key) == 0) {
            schema_field = &jsean->schema[i];
            break;
        }
    }

    if (!schema_field) {
        printf("Error: No schema found for key '%s'\n", key);
        return;
    }

    // Permission check
    if (!has_permission(schema_field, permission_level)) {
        printf("Permission Error: Permission level '%s' not allowed to access key '%s'\n", permission_level, key);
        return;
    }

    for (int i = 0; i < jsean->data_count; i++) {
        if (strcmp(jsean->data[i].key, key) == 0) {
            if (jsean->data[i].is_encrypted) {

                unsigned char decrypted_value[100];
                int decrypted_len = decrypt_field(jsean->data[i].value, jsean->data[i].value_len,
                                                jsean->data[i].tag, decrypted_value,
                                                jsean->data[i].iv, jsean);
                if (decrypted_len < 0) {
                    printf("Decryption failed for key '%s'\n", key);
                    return;
                }
                decrypted_value[decrypted_len] = '\0';
                if ((size_t)decrypted_len >= output_size) {
                    printf("Warning: Output buffer too small, truncating decrypted value for key '%s'\n", key);
                }
                snprintf(output, output_size, "%s", (char *)decrypted_value);
                printf("Retrieved decrypted value for key '%s'\n", key);
            } else {

                strncpy(output, (char *)jsean->data[i].value, jsean->data[i].value_len);
                output[jsean->data[i].value_len] = '\0';

            }
            return;
        }
    }
    printf("Error: Key '%s' not found\n", key);
}

// Example usage
#ifndef JSEAN_NO_MAIN
int main() {
    // Define schema with encryption required for specific fields
    SchemaField schema[] = {
        {"temperature", TYPE_INT, -50, 150, {}, {"editor", "admin"}, 0, 2, 0},
        {"humidity", TYPE_INT, 0, 100, {}, {"editor", "admin"}, 0, 2, 0},
        {"confidential_info", TYPE_STRING, 0, 0, {}, {"admin"}, 0, 1, 1}
    };

    JSean jsean;
    initialize(&jsean, schema, 3);

    // Store encrypted and plain fields with permission checking
    store_data_field(&jsean, "temperature", "72", "technician", "editor");
    store_data_field(&jsean, "humidity", "40", "technician", "editor");
    store_data_field(&jsean, "confidential_info", "SensitiveData123", "admin", "admin");

    // Retrieve fields (will decrypt if encrypted) with permission checking
    char output[100];
    retrieve_data_field(&jsean, "temperature", output, sizeof(output), "editor");
    printf("Temperature: %s\n", output);

    retrieve_data_field(&jsean, "confidential_info", output, sizeof(output), "admin");
    printf("Confidential Info: %s\n", output);

    // Attempt unauthorized access
    retrieve_data_field(&jsean, "confidential_info", output, sizeof(output), "editor");  // Should fail
    store_data_field(&jsean, "confidential_info", "NewSensitiveData", "technician", "editor");  // Should fail

    cleanup_jsean(&jsean);
    return 0;
}
#endif // JSEAN_NO_MAIN
