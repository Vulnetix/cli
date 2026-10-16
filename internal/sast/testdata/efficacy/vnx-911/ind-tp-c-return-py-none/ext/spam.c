#include <Python.h>

static PyObject *spam_reset(PyObject *self, PyObject *args)
{
    reset_state();
~>    return Py_None;
}
