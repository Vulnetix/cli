from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/welcome")
def welcome():
    display_name = request.args.get("name", "guest")
    banner = request.args.get("banner", "")
    page = f"""
    <html><body>
      <h1>Welcome back, {display_name}!</h1>
      <p>{banner}</p>
    </body></html>
    """
~>    return render_template_string(page)
