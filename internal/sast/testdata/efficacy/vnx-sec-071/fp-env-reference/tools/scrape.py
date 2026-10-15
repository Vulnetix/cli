import os
cookies = {"_gitlab_session": os.environ["GITLAB_SESSION"]}
header = f"_gitlab_session={session_id}"
