/* Write a program to demonstrate encryption and decryption of your full name using Playfair cipher. */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define SIZE 5

void prepareKeyTable(char key[], char keyTable[SIZE][SIZE]) {
    int i, j, k, flag = 0, *dicty;

    // Initialize the key table with zeros
    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            keyTable[i][j] = 0;
        }
    }

    // Mark the characters in the key as used
    dicty = (int *)calloc(26, sizeof(int));
    for (i = 0; i < strlen(key); i++) {
        if (key[i] != 'j')
            dicty[key[i] - 97] = 2;
    }

    // Fill the key table with the key
    for (i = 0, j = 0, k = 0; k < strlen(key); k++) {
        if (dicty[key[k] - 97] == 2) {
            dicty[key[k] - 97] -= 1;
            keyTable[i][j] = key[k];
            j++;
            if (j == 5) {
                i++;
                j = 0;
            }
        }
    }

    // Fill the remaining cells with the rest of the alphabet
    for (k = 0; k < 26; k++) {
        if (dicty[k] == 0) {
            keyTable[i][j] = (char)(k + 97);
            j++;
            if (j == 5) {
                i++;
                j = 0;
            }
        }
    }
}

void search(char keyTable[SIZE][SIZE], char a, char b, int arr[]) {
    int i, j;

    if (a == 'j')
        a = 'i';
    else if (b == 'j')
        b = 'i';

    for (i = 0; i < SIZE; i++) {
        for (j = 0; j < SIZE; j++) {
            if (keyTable[i][j] == a) {
                arr[0] = i;
                arr[1] = j;
            }
            if (keyTable[i][j] == b) {
                arr[2] = i;
                arr[3] = j;
            }
        }
    }
}

void encrypt(char keyTable[SIZE][SIZE], char pair[2]) {
    int i, a[4];

    search(keyTable, pair[0], pair[1], a);
    if (a[0] == a[2]) {
        pair[0] = keyTable[a[0]][(a[1] + 1) % SIZE];
        pair[1] = keyTable[a[2]][(a[3] + 1) % SIZE];
    } else if (a[1] == a[3]) {
        pair[0] = keyTable[(a[0] + 1) % SIZE][a[1]];
        pair[1] = keyTable[(a[2] + 1) % SIZE][a[3]];
    } else {
        pair[0] = keyTable[a[0]][a[3]];
        pair[1] = keyTable[a[2]][a[1]];
    }
}

void decrypt(char keyTable[SIZE][SIZE], char pair[2]) {
    int i, a[4];

    search(keyTable, pair[0], pair[1], a);
    if (a[0] == a[2]) {
        pair[0] = keyTable[a[0]][(a[1] - 1 + SIZE) % SIZE];
        pair[1] = keyTable[a[2]][(a[3] - 1 + SIZE) % SIZE];
    } else if (a[1] == a[3]) {
        pair[0] = keyTable[(a[0] - 1 + SIZE) % SIZE][a[1]];
        pair[1] = keyTable[(a[2] - 1 + SIZE) % SIZE][a[3]];
    } else {
        pair[0] = keyTable[a[0]][a[3]];
        pair[1] = keyTable[a[2]][a[1]];
    }
}

void formatInput(char *input) {
    int i;

    for (i = 0; i < strlen(input); i++) {
        if (input[i] == 'j')
            input[i] = 'i';
    }
}

void removeSpaces(char *input) {
    int i, j = 0;
    for (i = 0; i < strlen(input); i++) {
        if (input[i] != ' ') {
            input[j++] = tolower(input[i]);
        }
    }
    input[j] = '\0';
}

void playfairCipher(char key[], char input[]) {
    char keyTable[SIZE][SIZE];
    char cipherText[strlen(input)];
    int i, j;

    prepareKeyTable(key, keyTable);

    formatInput(input);
    removeSpaces(input);

    for (i = 0; i < strlen(input); i += 2) {
        if (input[i + 1] == '\0')
            input[i + 1] = 'x';

        if (input[i] == input[i + 1]) {
            input[i + 1] = 'x';
            i--;
        }
        
        char pair[2] = {input[i], input[i + 1]};
        
        encrypt(keyTable, pair);
        
        cipherText[i] = pair[0];
        cipherText[i + 1] = pair[1];
    }
    
    cipherText[strlen(input)] = '\0';
    
    printf("Encrypted Text: %s\n", cipherText);
    
    for (i = 0; i < strlen(cipherText); i += 2) {
        char pair[2] = {cipherText[i], cipherText[i + 1]};
        
        decrypt(keyTable, pair);
        
        input[i] = pair[0];
        input[i + 1] = pair[1];
    }
    
    input[strlen(cipherText)] = '\0';
    
    printf("Decrypted Text: %s\n", input);
}

int main() {
    char key[SIZE * SIZE];
    char input[100];

    printf("Enter the key (25 distinct letters excluding 'j'): ");
    scanf("%s", key);

    printf("Enter the text to be encrypted: ");
    scanf(" %[^\n]s", input);

    playfairCipher(key, input);

    return 0;
}

