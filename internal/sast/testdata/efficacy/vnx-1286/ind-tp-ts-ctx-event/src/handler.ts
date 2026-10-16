import { APIGatewayProxyEvent } from 'aws-lambda';

export const handler = async (event: APIGatewayProxyEvent) => {
~>  const payload = JSON.parse(event.body);
  return { statusCode: 200, body: JSON.stringify(payload.items.length) };
};
