import { gql } from 'graphql-tag';
import type { Request } from 'express';
import { apollo } from './apollo';

export async function findOrders(request: Request) {
  const status = request.query.status as string;
  const query = gql`
    query {
~>      orders(status: "${status}") {
        id
        total
      }
    }
  `;
  return apollo.query({ query });
}

export async function cancel(ctx: { params: Record<string, string> }) {
  const mutation = gql`
    mutation {
~>      cancelOrder(id: "${ctx.params.id}") { ok }
    }
  `;
  return apollo.mutate({ mutation });
}
