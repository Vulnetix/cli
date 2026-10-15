#include <Python.h>

static PyObject *is_ready(PyObject *, PyObject *)
{
    if (ready_flag())
~>        return Py_True;
    Py_INCREF(Py_False);
    return Py_False;
}

static PyObject *compare(PyObject *, PyObject *)
{
~>    return Py_NotImplemented;
}
