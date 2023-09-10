/* WAP to implement Euler's Totient Function. */
#include <stdio.h>

// Function to calculate Euler's Totient Function
int eulerTotient(int n) {
    int result = n; // Initialize result as n
    
    // Consider all prime factors of n and subtract their multiples from result
    int i;
    for (i = 2; i * i <= n; ++i) {
        if (n % i == 0) {
            // i is a prime factor of n
            while (n % i == 0) {
                n /= i;
            }
            result -= result / i;
        }
    }
    
    // If n has a prime factor greater than sqrt(n), it must be a prime
    if (n > 1) {
        result -= result / n;
    }
    
    return result;
}

int main() {
    int n;
    printf("Enter a positive integer: ");
    scanf("%d", &n);
    
    if (n <= 0) {
        printf("Please enter a positive integer.\n");
    } else {
        int totient = eulerTotient(n);
        printf("Euler's Totient Function(%d) = %d\n", n, totient);
    }
    
    return 0;
}

