import * as apigw from 'aws-cdk-lib/aws-apigateway';

export function api(scope: any) {
  return new apigw.RestApi(scope, 'Api', {
    defaultCorsPreflightOptions: {
~>      allowOrigins: apigw.Cors.ALL_ORIGINS,
      allowCredentials: true,
    },
  });
}
