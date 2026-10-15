import { gql } from "@apollo/client";
import { USER_FIELDS } from "./fragments";

export async function loadUser(client, id, logger) {
  const result = await client.query({
    query: gql`query User($id: ID!) { user(id: $id) { ...${USER_FIELDS} } }`,
    variables: { id },
  });
  logger.info(`SELECT for user ${id} returned ${result.data.user.name}`);
  const node = document.querySelector(`#user-${id}`);
  return { result, node };
}
