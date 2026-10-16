#include <Python.h>

static PyObject *first_str(PyObject *list)
{
    PyObject *item = PyList_GetItem(list, 0);
    PyObject *s = PyObject_Str(item);
~>    Py_DECREF(item);
    return s;
}
