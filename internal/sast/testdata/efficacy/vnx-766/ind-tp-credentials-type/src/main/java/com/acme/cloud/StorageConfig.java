package com.acme.cloud;

import java.util.Map;

public class StorageConfig {
    public String bucket;
    public String region;
~>    public AwsCredentials awsCredentials;
~>    public String accessToken;
~>    public Map<String, String> secrets;

    public static class AwsCredentials {
        private String accessKeyId;
        private String secretAccessKey;
    }
}
