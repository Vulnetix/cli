#include <Python.h>

static PyObject *
spam_reset(PyObject *self, PyObject *args)
{
    if (!PyArg_ParseTuple(args, ""))
        return NULL;
~>    return Py_None;
}

static PyObject *
spam_first(PyObject *self, PyObject *list)
{
    PyObject *item = PyList_GetItem(list, 0);
    if (item == NULL)
        return NULL;
    PyObject *s = PyObject_Str(item);
~>    Py_DECREF(item);
    return s;
}

static PyObject *
spam_lookup(PyObject *self, PyObject *dict)
{
    PyObject *v = PyDict_GetItemString(dict, "key");
    long n = PyLong_AsLong(v);
~>    Py_XDECREF(v);
    if (n > 0)
~>        return Py_True;
    Py_RETURN_FALSE;
}
