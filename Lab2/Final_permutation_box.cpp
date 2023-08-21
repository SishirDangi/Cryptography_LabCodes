#include <iostream>
#include <vector>
#include <string>

using namespace std;

vector<int> final_permutation(vector<int> input_bits) {
    vector<int> fp_table = {40, 8, 48, 16, 56, 24, 64, 32,
                            39, 7, 47, 15, 55, 23, 63, 31,
                            38, 6, 46, 14, 54, 22, 62, 30,
                            37, 5, 45, 13, 53, 21, 61, 29,
                            36, 4, 44, 12, 52, 20, 60, 28,
                            35, 3, 43, 11, 51, 19, 59, 27,
                            34, 2, 42, 10, 50, 18, 58, 26,
                            33, 1, 41, 9, 49, 17, 57, 25};
    
    vector<int> fp_result(64);
    for (size_t i = 0; i < fp_table.size(); ++i) {
        fp_result[i] = input_bits[fp_table[i] - 1];
    }
    return fp_result;
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
    vector<int> fp_result = final_permutation(input_bits);
    string fp_binary = vector_to_binary(fp_result);
    
    cout << "Input Binary: " << input_binary << endl;
    cout << "Final Permutation Result: " << fp_binary << endl;
    
    return 0;
}
