#pragma once

struct Node {
    int value;
    Node* left = nullptr;
    Node* right = nullptr;

~>    virtual ~Node() {
        delete left;
        delete right;
    }
};
