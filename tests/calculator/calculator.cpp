#include <iostream>
using namespace std;

// Function to add two numbers
float add(float x, float y) {
    return x + y;
}

// Function to subtract two numbers
float subtract(float x, float y) {
    return x - y;
}

// Function to multiply two numbers
float multiply(float x, float y) {
    return x * y;
}

// Function to divide two numbers
float divide(float x, float y) {
    if (y == 0) {
        cout << "Error! Cannot divide by zero." << endl;
        return 0;
    }
    return x / y;
}

int main() {
    char op;
    float num1, num2;

    cout << "Enter operator (+, -, *, /): ";
    cin >> op;

    cout << "Enter two operands: ";
    cin >> num1 >> num2;

    switch(op) {
        case '+':
            cout << "Result: " << add(num1, num2);
            break;
        case '-':
            cout << "Result: " << subtract(num1, num2);
            break;
        case '*':
            cout << "Result: " << multiply(num1, num2);
            break;
        case '/':
            cout << "Result: " << divide(num1, num2);
            break;
        default:
            // If the operator is other than +, -, *, or /, error message is shown
            cout << "Error! Invalid operator";
            break;
    }

    return 0;
}
