#include <iostream>
#include <vector>
#include <algorithm> // for rotate

using namespace std;

// Permutation Choice 1 (PC-1) table
const int pc1_table[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

// Left shift schedule for each round
const int left_shift_schedule[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

// Function to perform the left circular shift on a vector
void left_circular_shift(vector<int>& bits, int shift) {
    rotate(bits.begin(), bits.begin() + shift, bits.end());
}

// Function to generate subkeys for each round
vector<vector<int>> generate_subkeys(vector<int> key_bits) {
    vector<vector<int>> subkeys(16, vector<int>(48));
    vector<int> shifted_key(56);
    
    for (int round = 0; round < 16; ++round) {
        // Apply the PC-1 permutation to the key
        for (int i = 0; i < 56; ++i) {
            shifted_key[i] = key_bits[pc1_table[i] - 1];
        }
        
        // Perform the left circular shift for the current round
        left_circular_shift(shifted_key, left_shift_schedule[round]);
        
        // Apply the PC-2 permutation to generate the subkey
        for (int i = 0; i < 48; ++i) {
            subkeys[round][i] = shifted_key[i];
        }
    }
    
    return subkeys;
}

int main() {
    // Example input key: 01111011011011010101010101111000111100001111000010101010
    vector<int> key_bits = {
        0, 1, 1, 1, 1, 0, 1, 1,
        0, 1, 1, 0, 1, 1, 0, 1,
        0, 1, 0, 1, 0, 1, 0, 1,
        0, 1, 0, 1, 0, 1, 0, 1,
        0, 1, 1, 1, 0, 0, 0, 1,
        1, 1, 1, 0, 0, 0, 0, 1,
        1, 0, 1, 0, 1, 0, 1, 0,
        1, 0, 1, 0, 1, 0, 1, 0
    };
    
    // Generate subkeys for each round
    vector<vector<int>> subkeys = generate_subkeys(key_bits);
    
    // Print the generated subkeys
    for (int round = 0; round < 16; ++round) {
        cout << "Round " << round + 1 << " Subkey: ";
        for (int bit : subkeys[round]) {
            cout << bit;
        }
        cout << endl;
    }
    
    return 0;
}
