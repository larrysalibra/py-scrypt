/*-
 * Copyright 2010 Magnus Hallin
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <Python.h>

#include "scryptenc/scryptenc.h"

static PyObject *ScryptError;

static const char *errorCodes[] = {
    "success",
    "getrlimit or sysctl(hw.usermem) failed",
    "clock_getres or clock_gettime failed",
    "error computing derived key",
    "could not read salt from /dev/urandom",
    "error in OpenSSL",
    "malloc failed",
    "data is not a valid scrypt-encrypted block",
    "unrecognized scrypt format",
    "decrypting file would take too much memory",
    "decrypting file would take too long",
    "password is incorrect",
    "error writing output file",
    "error reading input file"
};

static PyObject *scrypt_encrypt(PyObject *self, PyObject *args) {
		const char *input, *password;
    int inputlen, passwordlen;
    int errorcode;
    double maxtime;
    uint8_t *outbuf;
    
    if (!PyArg_ParseTuple(args, "s#s#d", &input, &inputlen, &password, &passwordlen, &maxtime)) {
        return NULL;
    }

    outbuf = PyMem_Malloc(inputlen+129);

		Py_BEGIN_ALLOW_THREADS;
    errorcode = scryptenc_buf((uint8_t *) input, inputlen, 
                              outbuf, 
                              (uint8_t *) password, passwordlen,
                              0, 0, maxtime);
		Py_END_ALLOW_THREADS;

    PyObject *value = NULL;
    if (errorcode != 0) {
        PyErr_Format(ScryptError, "%s", errorCodes[errorcode]);
        PyErr_SetNone(ScryptError);
    } else {
        value = Py_BuildValue("y#", outbuf, inputlen+128);
    }
    PyMem_Free(outbuf);
    
    return value;
}

static PyObject *scrypt_decrypt(PyObject *self, PyObject *args) {
		const char *input, *password;
    int inputlen, passwordlen;
		size_t outputlen;
    int errorcode;
    double maxtime;
    uint8_t *outbuf;
    
    if (!PyArg_ParseTuple(args, "s#s#d", &input, &inputlen, &password, &passwordlen, &maxtime)) {
        return NULL;
    }

    outbuf = PyMem_Malloc(inputlen);

		Py_BEGIN_ALLOW_THREADS;
    errorcode = scryptdec_buf((const uint8_t *) input, inputlen,
                              outbuf, &outputlen,
                              (const uint8_t *) password, passwordlen,
                              0, 0, maxtime);
		Py_END_ALLOW_THREADS;

    PyObject *value = NULL;
    if (errorcode != 0) {
        PyErr_Format(ScryptError, "%s", errorCodes[errorcode]);
    } else {
        value = Py_BuildValue("s#", outbuf, outputlen);
    }
    PyMem_Free(outbuf);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "encrypt", scrypt_encrypt, METH_VARARGS, "encrypt(input, password, maxtime): str; encrypt a string" },
    { "decrypt", scrypt_decrypt, METH_VARARGS, "decrypt(input, password, maxtime): str; decrypt a string" },
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef scryptmodule = {
		PyModuleDef_HEAD_INIT,
		"scrypt",
		NULL,
		-1,
		ScryptMethods
};

PyMODINIT_FUNC PyInit_scrypt(void) {
    PyObject *m = PyModule_Create(&scryptmodule);
    
    if (m == NULL) {
        return NULL;
    }
    
    ScryptError = PyErr_NewException("scrypt.error", NULL, NULL);
    Py_INCREF(ScryptError);
    PyModule_AddObject(m, "error", ScryptError);
		return m;
}
