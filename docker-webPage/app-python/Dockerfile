FROM python:3.7.0-slim-stretch

ENV BIND_PORT 5000
ENV REDIS_HOST redis.default
ENV REDIS_PORT 6379

COPY ./requirements.txt /requirements.txt
COPY ./app.py /app.py

RUN pip install -r /requirements.txt

EXPOSE $BIND_PORT

CMD [ "python", "/app.py" ]
