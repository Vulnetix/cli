from alibabacloud_tea_openapi.models import Config

config = Config(
~>    access_key_id="LTAI@@sample:[a-z][0-9][a-z0-9]{18}@@",
    access_key_secret=os.environ["ALIYUN_SECRET"],
    endpoint="ecs.cn-hangzhou.aliyuncs.com",
)
