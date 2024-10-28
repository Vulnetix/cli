import pathlib
import tomllib
import time
from datetime import datetime, timedelta, timezone

from httpx import Client, Response, HTTPError

config = tomllib.loads(pathlib.Path('.dev.vars').read_text())
ACCOUNT_ID = 'e302589106b4c4287aebe65763eb4f80'
PROJECT_NAME = 'vulnetix'
ENDPOINT = f'https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/pages/projects/{PROJECT_NAME}/deployments'
CF_API_TOKEN = config['CLOUDFLARE_API_TOKEN']
EXPIRATION_BEFORE = datetime.now(timezone.utc) - timedelta(days=7)
HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {CF_API_TOKEN}',
}
print(HEADERS)

def delete_deployments(client: Client):
    page = 1
    total_deleted = 0
    i = 0
    while True:
        i += 1
        r = client.get(ENDPOINT, headers=HEADERS, params={'page': page})
        check_status(r)
        deployments = r.json()

        results = deployments['result']
        print(f'{i}: page {page}, got {len(results)} deployments, total deleted {total_deleted}')
        deleted = 0

        for deployment in results:
            created_on = datetime.fromisoformat(deployment['created_on'])
            if created_on < EXPIRATION_BEFORE:
                deployment_id = deployment['id']
                start = time.time()
                delete(client, deployment_id)
                time_taken = time.time() - start
                print(f'  deleted {deployment_id} (created {created_on:%Y-%m-%d}), took {time_taken:.2f}s')

                # see if this is long enough to avoid rate limiting?
                time.sleep(0.25)
                deleted += 1

        total_deleted += deleted
        if deleted == 0:
            # only increment the page number if we didn't delete anything
            page += 1


def delete(client: Client, deployment_id: str) -> int:
    last_error = None
    for retry in range(4):
        try:
            r = client.delete(f'{ENDPOINT}/{deployment_id}', headers=HEADERS, params={'force': 'true'})
            check_status(r)
        except HTTPError as e:
            print(f'    retry {retry} after {e}')
            last_error = e
        else:
            return retry

    raise last_error


def check_status(response: Response):
    if not (200 <= response.status_code < 300):
        raise HTTPError(f'HTTP status {response.status_code}: {response.text}')

if __name__ == "__main__":
    with Client(timeout=10) as c:
        delete_deployments(c)
