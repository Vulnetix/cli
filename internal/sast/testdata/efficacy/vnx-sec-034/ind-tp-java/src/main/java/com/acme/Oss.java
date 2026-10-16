public class Oss {
    private static final String ENDPOINT = "https://oss-cn-beijing.aliyuncs.com";
    public static OSS build() {
        return new OSSClientBuilder().build(ENDPOINT,
~>            "LTAI@@sample:[A-Z][0-9][A-Za-z0-9]{18}@@",
            System.getenv("OSS_SECRET"));
    }
}
