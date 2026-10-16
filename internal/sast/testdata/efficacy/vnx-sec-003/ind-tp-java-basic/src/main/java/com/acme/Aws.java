package com.acme;

import com.amazonaws.auth.BasicAWSCredentials;

public class Aws {
    BasicAWSCredentials c = new BasicAWSCredentials(
        System.getenv("KEY_ID"),
~>        "@@sample:[A-Za-z0-9/+]{40}@@");
}
