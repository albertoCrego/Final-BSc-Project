#FROM python:3.7.0-slim-stretch
FROM arm32v7/python:3.7.0-slim-stretch

ENV BIND_PORT 5000
ENV REDIS_HOST redis.default
ENV REDIS_PORT 6379

COPY ./requirements.txt /requirements.txt
COPY ./app.py /app.py

#RUN pip install -r /requirements.txt
#RUN pip install flask

RUN pipenv install --system

EXPOSE $BIND_PORT

CMD [ "python3", "/app.py" ]
