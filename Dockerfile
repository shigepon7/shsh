FROM python:3-alpine
EXPOSE 51964
RUN pip install --upgrade pip && pip install mysql-connector-python requests
WORKDIR /usr/src
COPY shsh.py /usr/src/shsh.py
RUN chmod +x /usr/src/shsh.py
CMD ["./shsh.py", "-t", "<slack API access token>", "-c", "#<channel name>", "-m", "#<channel name>", "-h", "<mysql server host address>", "-u", "<mysql user>", "-p", "<mysql password>", "-d", "<mysql database name>"]
