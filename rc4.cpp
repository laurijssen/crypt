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
    
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
