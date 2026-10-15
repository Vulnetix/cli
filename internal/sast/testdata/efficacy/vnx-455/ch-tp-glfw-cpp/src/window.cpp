#include <GLFW/glfw3.h>
#include <iostream>

GLFWwindow *createWindow(int w, int h)
{
~>    if (!glfwInit()) {
        std::cerr << "glfwInit failed" << std::endl;
    }
    return glfwCreateWindow(w, h, "viewer", nullptr, nullptr);
}
