/* WAP to find primitive roots */
#include <stdio.h>
#include <stdbool.h>

// Function to calculate the power of a number (a^b % m)
int power(int a, int b, int m) {
    int result = 1;
    a = a % m;
    while (b > 0) {
        if (b % 2 == 1) {
            result = (result * a) % m;
        }
        b = b / 2;
        a = (a * a) % m;
    }
    return result;
}

// Function to check if 'a' is a primitive root modulo 'p'
bool isPrimitiveRoot(int a, int p) {
    // Check if 'a' is relatively prime to 'p'
    if (gcd(a, p) != 1) {
        return false;
    }

    // Calculate Euler's Totient function (phi)
    int phi = p - 1;

    // Check if 'a' raised to the power of each divisor of phi
    // modulo p results in a unique value
    int i;
    for (i = 2; i <= phi; i++) {
        if (phi % i == 0) {
            // Check if a^(phi/i) % p == 1
            if (power(a, phi / i, p) == 1) {
                return false;
            }
        }
    }

    // If all checks pass, 'a' is a primitive root modulo 'p'
    return true;
}

// Function to find primitive roots modulo 'p'
void findPrimitiveRoots(int p) {
    printf("Primitive roots modulo %d are: ", p);
    int a;
    for (a = 2; a < p; a++) {
        if (isPrimitiveRoot(a, p)) {
            printf("%d ", a);
        }
    }
    printf("\n");
}

// Function to calculate the greatest common divisor (GCD) of two numbers
int gcd(int a, int b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a % b);
}

int main() {
    int p;
    printf("Enter a prime number p: ");
    scanf("%d", &p);

    if (p <= 1) {
        printf("p must be greater than 1.\n");
        return 1;
    }

    findPrimitiveRoots(p);

    return 0;
}

