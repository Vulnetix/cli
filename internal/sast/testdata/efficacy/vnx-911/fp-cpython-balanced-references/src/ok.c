#include <Python.h>

static PyObject *
ok_reset(PyObject *self, PyObject *args)
{
    Py_RETURN_NONE;
}

static PyObject *
ok_none(PyObject *self, PyObject *args)
{
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *
ok_first(PyObject *self, PyObject *list)
{
    PyObject *item = PyList_GetItem(list, 0);
    Py_INCREF(item);
    PyObject *s = PyObject_Str(item);
    Py_DECREF(item);
    return s;
}

static PyObject *
ok_attr(PyObject *self, PyObject *obj)
{
    PyObject *name = PyObject_GetAttrString(obj, "name");
    if (name == NULL)
        return NULL;
    long n = PyObject_Length(name);
    Py_DECREF(name);
    if (n > 0)
        return Py_NewRef(Py_True);
    return PyBool_FromLong(0);
}

static PyObject *
ok_reuse(PyObject *self, PyObject *dict)
{
    PyObject *v = PyDict_GetItemString(dict, "key");
    v = PyNumber_Long(v);
    Py_XDECREF(v);
    return Py_NewRef(Py_None);
}
