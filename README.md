# SHSH (SHigepon SmartHome)

## Usage

1. Create Slack bot account.
2. Prepare a MySQL server.
3. Edit `Dockerfile`.
    1. Slack bot token (-t).
    2. Slack channel name (-c, -m).
    3. MySQL database settings (-h -u -p -d).
4. Build docker image.
```
docker build -t shsh .
```
5. Run docker container.
```
docker run --rm --net=host shsh
```

## Author

- Daisuke SHIGETA a.k.a. @shigepon7
