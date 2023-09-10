/* WAP to implement RSA algorithm. */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to check if a number is prime
int is_prime(int n) {
    if (n <= 1)
        return 0;
    if (n <= 3)
        return 1;

    if (n % 2 == 0 || n % 3 == 0)
        return 0;
	int i;
    for (i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0)
            return 0;
    }

    return 1;
}

// Function to find the greatest common divisor (GCD) of two numbers
int gcd(int a, int b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

// Function to generate RSA key pair
void generate_key_pair(int *public_key, int *private_key, int *n) {
    int p, q, phi, e, d;

    // Step 1: Select two prime numbers, p and q
    do {
        p = rand() % 50 + 50;  // Adjust the range as needed
    } while (!is_prime(p));

    do {
        q = rand() % 50 + 50;  // Adjust the range as needed
    } while (!is_prime(q));

    *n = p * q;
    phi = (p - 1) * (q - 1);

    // Step 2: Choose a public exponent 'e'
    do {
        e = rand() % (phi - 2) + 2;
    } while (gcd(e, phi) != 1);

    // Step 3: Calculate the private exponent 'd'
    for (d = 2; d < phi; d++) {
        if ((e * d) % phi == 1)
            break;
    }

    *public_key = e;
    *private_key = d;
}

// Function to encrypt a message using the public key
int encrypt(int plaintext, int public_key, int n) {
    return (int)(pow(plaintext, public_key)) % n;
}

// Function to decrypt a message using the private key
int decrypt(int ciphertext, int private_key, int n) {
    return (int)(pow(ciphertext, private_key)) % n;
}

int main() {
    int public_key, private_key, n;
    int plaintext, ciphertext, decrypted_text;

    // Generate RSA key pair
    generate_key_pair(&public_key, &private_key, &n);

    // Input plaintext message
    printf("Enter the plaintext message (an integer): ");
    scanf("%d", &plaintext);

    // Encryption
    ciphertext = encrypt(plaintext, public_key, n);
    printf("Encrypted message: %d\n", ciphertext);

    // Decryption
    decrypted_text = decrypt(ciphertext, private_key, n);
    printf("Decrypted message: %d\n", decrypted_text);

    return 0;
}

