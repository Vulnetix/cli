FROM python:3.12-slim
RUN pip install transformers
~>ENV HUGGING_FACE_HUB_TOKEN=hf_@@sample:[A-Za-z0-9]{34}@@
CMD ["python", "serve.py"]
