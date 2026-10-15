#include <Python.h>

static PyObject *
is_even(PyObject *self, PyObject *arg)
{
    long v = PyLong_AsLong(arg);
    if (v == -1 && PyErr_Occurred())
        return NULL;
    if (v % 2 == 0)
        Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

static PyObject *
noop(PyObject *self, PyObject *unused)
{
    return Py_NewRef(Py_None);
}

static PyObject *
first(PyObject *self, PyObject *list)
{
    PyObject *item = PyList_GetItem(list, 0);
    if (item == NULL)
        return NULL;
    Py_INCREF(item);
    return item;
}

static PyObject *
owned(PyObject *self, PyObject *arg)
{
    PyObject *s = PyObject_Str(arg);
    if (s == NULL)
        return NULL;
    Py_ssize_t n = PyUnicode_GetLength(s);
    Py_DECREF(s);
    return PyLong_FromSsize_t(n);
}
