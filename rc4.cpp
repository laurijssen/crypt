// rc4.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>

typedef struct
{
    char table[256];
    char index[2];
} RC4_key_t;

void RC4_setup_key(char const key_text[], size_t len, RC4_key_t* key)
{
    int i;
    char temp, e;

    for (i = 0; i < 256; i++)
    {
        key->table[i] = i;
    }

    key->index[0] = 0;
    key->index[1] = 0;

    for (i = 0, e = 0; i < 256; i++)
    {
        e += key_text[i % len] + key->table[i];

        temp = key->table[i];
        key->table[i] = key->table[e];
        key->table[e] = temp;
    }
}

void RC4_encrypt(char const plaintext[], char cyphertext[], size_t len, RC4_key_t* key)
{
    int i;
    char temp;

    for (i = 0; i < len; i++)
    {
        key->index[1] += key->table[++key->index[0]];

        temp = key->table[key->index[0]];
        key->table[key->index[0]] = key->table[key->index[1]];
        key->table[key->index[1]] = temp;

        cyphertext[i] =
            plaintext[i] ^
            key->table[key->table[key->index[0]] +
            key->table[key->index[1]]
        ];
    }
}

int main()
{
    RC4_key_t key = { 0 };

    RC4_setup_key("1234", 4, &key);

    char cypher[256] = { 0 };

    RC4_encrypt("sometest", cypher, 8, &key);
}
