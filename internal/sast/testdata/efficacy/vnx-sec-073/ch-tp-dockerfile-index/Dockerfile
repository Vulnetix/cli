FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
~>RUN pip install --no-cache-dir --index-url https://deploy:Xk9pQ2mZv7Lr@@@sample:p[y]pi[.]in[t]er[n]al[.]ac[m]e[.][i]o[/][s]im[p]le@@ -r @@sample:r[e]qu[i]re[m]en[t]s[.][t]xt@@
COPY . .
CMD ["gunicorn", "app:app"]
