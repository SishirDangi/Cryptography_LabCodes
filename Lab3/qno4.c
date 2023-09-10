/* WAP to implement Diffie-Hellman Key Exchange Algorithm. */
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to calculate (base^exponent) % modulus efficiently
long long int mod_pow(long long int base, long long int exponent, long long int modulus) {
    long long int result = 1;
    base = base % modulus;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1;
        base = (base * base) % modulus;
    }

    return result;
}

int main() {
    long long int p, g, a, b;

    // Step 1: Both parties agree on a prime number 'p' and a primitive root 'g'
    printf("Enter a prime number (p): ");
    scanf("%lld", &p);

    printf("Enter a primitive root modulo p (g): ");
    scanf("%lld", &g);

    // Step 2: Alice generates a private key 'a'
    printf("Alice, enter your private key (a): ");
    scanf("%lld", &a);

    // Step 3: Bob generates a private key 'b'
    printf("Bob, enter your private key (b): ");
    scanf("%lld", &b);

    // Step 4: Both Alice and Bob calculate their public keys
    long long int A = mod_pow(g, a, p);
    long long int B = mod_pow(g, b, p);

    // Step 5: Alice and Bob exchange their public keys A and B securely

    // Step 6: Both Alice and Bob calculate the shared secret key
    long long int secret_key_A = mod_pow(B, a, p);
    long long int secret_key_B = mod_pow(A, b, p);

    printf("Shared Secret Key (Alice): %lld\n", secret_key_A);
    printf("Shared Secret Key (Bob): %lld\n", secret_key_B);

    if (secret_key_A == secret_key_B) {
        printf("Shared secrets match. Secure communication established!\n");
    } else {
        printf("Shared secrets do not match. Communication compromised!\n");
    }

    return 0;
}

