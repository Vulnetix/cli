package com.acme.storage;

import com.amazonaws.auth.BasicAWSCredentials;

public class S3Factory {
    private static final BasicAWSCredentials CREDS = new BasicAWSCredentials(
~>            "@@sample:AKIA[A-Z2-7]{16}@@",
            System.getenv("AWS_SECRET_ACCESS_KEY"));
}
