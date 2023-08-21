#include <iostream>
#include <vector>

using namespace std; // Added the using directive

// S-box 1
const int s_box1[4][16] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
    {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
    {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
    {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
};

// Function to perform S-box substitution
int s_box_substitution(int row, int column) {
    return s_box1[row][column];
}

int main() {
    // Example input: 0010 (row: 0, column: 2)
    int row = 0;
    int column = 2;
    
    // Perform S-box substitution
    int s_box_result = s_box_substitution(row, column);
    
    cout << "Input: " << row << column << endl;
    cout << "S-box Output: " << s_box_result << endl;
    
    return 0;
}
