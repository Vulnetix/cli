#define PY_SSIZE_T_CLEAN
#include <Python.h>

static PyObject *
is_even(PyObject *self, PyObject *arg)
{
    long v = PyLong_AsLong(arg);
    if (v == -1 && PyErr_Occurred())
        return NULL;
    if (v % 2 == 0)
~>        return Py_True;
~>    return Py_False;
}
