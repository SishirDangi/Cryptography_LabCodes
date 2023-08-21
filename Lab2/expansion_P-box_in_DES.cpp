#include <iostream>
#include <vector>

using namespace std;

vector<int> expansion_p_box(vector<int> input_bits) {
    vector<int> ep_table = {32, 1, 2, 3, 4, 5,
                            4, 5, 6, 7, 8, 9,
                            8, 9, 10, 11, 12, 13,
                            12, 13, 14, 15, 16, 17,
                            16, 17, 18, 19, 20, 21,
                            20, 21, 22, 23, 24, 25,
                            24, 25, 26, 27, 28, 29,
                            28, 29, 30, 31, 32, 1};
    
    vector<int> ep_result(48);
    for (size_t i = 0; i < ep_table.size(); ++i) {
        ep_result[i] = input_bits[ep_table[i] - 1];
    }
    return ep_result;
}

int main() {
    vector<int> input_bits = {1, 0, 1, 0, 1, 0, 1, 0,
                              0, 1, 1, 0, 1, 1, 0, 0,
                              1, 0, 0, 1, 0, 1, 0, 1,
                              0, 1, 0, 1, 0, 1, 0, 1};
    
    vector<int> ep_result = expansion_p_box(input_bits);
    
    cout << "Input Bits: ";
    for (int bit : input_bits) {
        cout << bit;
    }
    cout << endl;
    
    cout << "Expansion P-box Result: ";
    for (int bit : ep_result) {
        cout << bit;
    }
    cout << endl;
    
    return 0;
}
