import json
import subprocess


def dispatch(resp):
    call = resp.choices[0].message.tool_calls[0]
    args = json.loads(call.function.arguments)
    if call.function.name == "disk_usage":
        return subprocess.run(["df", "-h", args["mount"]], capture_output=True, text=True).stdout
    raise ValueError("unknown tool")
