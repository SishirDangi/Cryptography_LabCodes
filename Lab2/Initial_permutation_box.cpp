#include <iostream>
#include <vector>
#include <string>

using namespace std;

vector<int> initial_permutation(vector<int> input_bits) {
    vector<int> ip_table = {58, 50, 42, 34, 26, 18, 10, 2,
                            60, 52, 44, 36, 28, 20, 12, 4,
                            62, 54, 46, 38, 30, 22, 14, 6,
                            64, 56, 48, 40, 32, 24, 16, 8,
                            57, 49, 41, 33, 25, 17, 9, 1,
                            59, 51, 43, 35, 27, 19, 11, 3,
                            61, 53, 45, 37, 29, 21, 13, 5,
                            63, 55, 47, 39, 31, 23, 15, 7};
    
    vector<int> ip_result(64);
    for (size_t i = 0; i < ip_table.size(); ++i) {
        ip_result[i] = input_bits[ip_table[i] - 1];
    }
    return ip_result;
}

vector<int> binary_to_vector(string binary_string) {
    vector<int> bit_vector;
    for (char bit : binary_string) {
        bit_vector.push_back(bit - '0');
    }
    return bit_vector;
}

string vector_to_binary(vector<int> bit_vector) {
    string binary_string;
    for (int bit : bit_vector) {
        binary_string += to_string(bit);
    }
    return binary_string;
}

int main() {
    string input_binary = "110010101111110011001010101011110011001010101011";
    
    vector<int> input_bits = binary_to_vector(input_binary);
    vector<int> ip_result = initial_permutation(input_bits);
    string ip_binary = vector_to_binary(ip_result);
    
    cout << "Input Binary: " << input_binary << endl;
    cout << "Initial Permutation Result: " << ip_binary << endl;
    
    return 0;
}
