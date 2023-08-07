/* Write a program to demonstrate encryption and decryption of your full name using Caesar Cipher*/
#include <stdio.h>
#include <string.h>

// Function to encrypt a message using Caesar Cipher
void encrypt(char message[], int key) {
    int i;
    for (i = 0; message[i] != '\0'; ++i) {
        if (message[i] >= 'A' && message[i] <= 'Z') {
            message[i] = (message[i] - 'A' + key) % 26 + 'A';
        } else if (message[i] >= 'a' && message[i] <= 'z') {
            message[i] = (message[i] - 'a' + key) % 26 + 'a';
        }
    }
}

// Function to decrypt a message using Caesar Cipher
void decrypt(char message[], int key) {
    int i;
    for (i = 0; message[i] != '\0'; ++i) {
        if (message[i] >= 'A' && message[i] <= 'Z') {
            message[i] = (message[i] - 'A' - key + 26) % 26 + 'A';
        } else if (message[i] >= 'a' && message[i] <= 'z') {
            message[i] = (message[i] - 'a' - key + 26) % 26 + 'a';
        }
    }
}

int main() {
    char name[100];
    int key;

    printf("Enter your full name: ");
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = '\0'; // Remove the newline character from fgets

    printf("Enter the encryption key (0-25): ");
    scanf("%d", &key);

    encrypt(name, key);
    printf("Encrypted name: %s\n", name);

    decrypt(name, key);
    printf("Decrypted name: %s\n", name);

    return 0;
}

