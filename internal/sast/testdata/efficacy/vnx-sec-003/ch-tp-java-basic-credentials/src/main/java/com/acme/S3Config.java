package com.acme;

import com.amazonaws.auth.BasicAWSCredentials;

public class S3Config {
    BasicAWSCredentials creds() {
        return new BasicAWSCredentials(
                System.getenv("AWS_ACCESS_KEY_ID"),
~>                "@@sample:[A-Za-z0-9/+]{40}@@");
    }
}
