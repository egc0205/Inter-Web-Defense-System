#based on the Dockerfiles in Shuffles Python github repo
FROM frikky/shuffle:app_sdk

COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

COPY src /app
WORKDIR /app
CMD ["python", "app.py", "--log-level", "DEBUG"]
