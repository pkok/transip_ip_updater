# transip_ip_updater

This project tries to keep the DNS A records of your TransIP-registered domain names pointing to your current IP address.  

This Python project should be executed every so often, just to see if your IP address has changed.  I said, "let's do every 10 minutes", and cron will do so.  Most of the code assumes it's run in a Docker container.

The flow of this program:

1. Get the current external IP address by making a call to IPify's API.
2. If current external IP is the same as stored IP (see 6.): exit successfully.
3. Authenticate with TransIP by using the private key file -- see [Setup](#setup).
4. Get all domains, matching the provided tags -- see [Setup](#setup)
5. For each domain:
    1. Check for each DNS record if it's an A records and pointing to another IP than your current one.
    2. If both conditions are true, update the record's content to the current external IP.
6. If all changes were successfull: store this IP.

## Environment variables

| Variable name         | Default value                   | Description                                                                           |
|:----------------------|:--------------------------------|:--------------------------------------------------------------------------------------|
| `PRIVATE_KEY_FILE`    | `"/config/private_key.pem"`     | Path to private key, generated by TransIP API.                                        |
| `LAST_UPDATE_IP_FILE` | `"/config/last_updated_ip.txt"` | Path to the file containing the cached IP.                                            |
| `USERNAME`            | `""`                            | Your TransIP username.                                                                |
| `DOMAIN_TAGS`         | `""`                            | Comma-separated list of tags; only those domains are inspected.                       |
| `LOGGING_LEVEL`       | `"INFO"`                        | [Logging level](https://docs.python.org/3/library/logging.html#levels) being applied. |

## Setup

### Authentication

Before using this software, you have to inform TransIP you want to work with its API.  Do the following in the TransIP control panel first:

- Go to <https://www.transip.nl/cp/account/api/> and create a key pair.
- Store the path to the private key file in environment variable  PRIVATE_KEY_FILE`.

### Domain tags

Domains can be tagged in TransIP's control panel.  This software uses those tags for filtering purposes: only those domains are investigated (and perhaps modified) if they match with your tags.

### Docker compose

```
?
```

## Note

There is **no** optimization happening here; it will just figure out your IP address, and contact TransIP every 10 minutes!  This has been put together in a day by someone not very often developing these types of application.  DNS is new.  Docker is new.  RESTful APIs are new.  No need to overcomplicate this.
