/* WAP to implement Elgamal Cryptographic System. */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to calculate (base^exponent) % modulus
long long mod_pow(long long base, long long exponent, long long modulus) {
    long long result = 1;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

int main() {
    long long p, g, x, y, k, m, c1, c2, decrypted_message;

    // Step 1: Choose a large prime number 'p' and a primitive root 'g' modulo 'p'
    printf("Enter a prime number (p): ");
    scanf("%lld", &p);
    printf("Enter a primitive root (g) modulo p: ");
    scanf("%lld", &g);

    // Step 2: Generate the private key 'x'
    printf("Enter your private key (x): ");
    scanf("%lld", &x);

    // Calculate the public key 'y' using y = g^x mod p
    y = mod_pow(g, x, p);

    // Step 3: Encryption
    printf("Enter the message to encrypt (m): ");
    scanf("%lld", &m);

    // Generate a random number 'k'
    k = rand() % (p - 2) + 1;

    // Calculate c1 = g^k mod p
    c1 = mod_pow(g, k, p);

    // Calculate c2 = (m * y^k) mod p
    c2 = (m * mod_pow(y, k, p)) % p;

    printf("Encrypted message (c1, c2): (%lld, %lld)\n", c1, c2);

    // Step 4: Decryption
    // Calculate the inverse of c1^x mod p
    long long c1_x_inverse = mod_pow(c1, x, p);
    c1_x_inverse = mod_pow(c1_x_inverse, p - 2, p);

    // Calculate the decrypted message as (c2 * c1^x_inverse) mod p
    decrypted_message = (c2 * c1_x_inverse) % p;

    printf("Decrypted message: %lld\n", decrypted_message);

    return 0;
}

