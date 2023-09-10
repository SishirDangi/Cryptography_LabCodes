/* WAP to implement Miller-Rabin Algorithm. */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

// Function to perform modular exponentiation (a^b % m)
long long modExp(long long a, long long b, long long m) {
    long long result = 1;
    a %= m;
    while (b > 0) {
        if (b % 2 == 1)
            result = (result * a) % m;
        a = (a * a) % m;
        b /= 2;
    }
    return result;
}

// Miller-Rabin primality test
bool isPrimeMillerRabin(long long n, int k) {
    if (n <= 1 || n == 4)
        return false;
    if (n <= 3)
        return true;

    // Find d such that n - 1 = 2^r * d
    long long d = n - 1;
    while (d % 2 == 0)
        d /= 2;

    // Witness loop
    int i;
    for (i = 0; i < k; i++) {
        // Generate a random number 'a' in the range [2, n - 2]
        long long a = 2 + rand() % (n - 3);

        // Compute x = a^d % n
        long long x = modExp(a, d, n);

        if (x == 1 || x == n - 1)
            continue;

        // Repeat squaring for 'r' times
        int r;
        for (r = 1; r < d; r++) {
            x = modExp(x, 2, n);
            if (x == 1)
                return false; // Composite
            if (x == n - 1)
                break;
        }

        if (x != n - 1)
            return false; // Composite
    }

    return true; // Probably prime
}

int main() {
    long long num;
    int k;

    printf("Enter a number: ");
    scanf("%lld", &num);

    printf("Enter the number of iterations (k): ");
    scanf("%d", &k);

    if (isPrimeMillerRabin(num, k))
        printf("%lld is probably prime.\n", num);
    else
        printf("%lld is composite.\n", num);

    return 0;
}

