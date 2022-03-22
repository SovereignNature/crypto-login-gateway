# Crypto Login Gateway

Gateway that augments a given service with authentication and access control through blockchain addresses and signatures.

## Project Structure

This project was developed with `nodejs`'s `express` framework.

At the root of this project, there are two directories: `gateway` and `test`.

### Gateway

The `gateway` directory contains the source code for this project.
The `main.js` file defines the endpoints and configurations of this service.
The `db.js` file wraps database interactions, including its initial set-up.
The `auth.js` file wraps authentication operations.
The `utils.js` file contains a set of functions usefull throughout the rest of the project.

### Test

The `test` directory contains the source code for a test client for our api.
The `test.js` file contains examples of some test cases and their expecte results.
The `utils.js` file is the same of `../gateway/utils.js`.

### Other Files

The `docker-compose.yml` file contains the configurations of a testing deployment of our api and test client as well as a postgre database and a simple hello-world backend service to be proxified by our api.

The `gateway.yml` file contains an exemple specification of this service for a Kubernetes deployment.

## Deployment

Before deploying this service, you must create a `whitelist.txt` file containning the allowed addresses, with the following format:
```
address;name;enabled
<Alice's address>;"Alice";true
```
The `name` field is just a tag and is optional.
The `enabled` field determines if the respective address should be allowed or not.

In addition, you must also create a `.env` file contianing the configurations for the gateway, with the following entries:
```
JWT_SECRET=<string> # Secret used to sign each authentication token issued
JWT_DURATION=<seconds> # Validity of each authentication token issued, in seconds

WHITELIST_FILE=/login-gateway/whitelist.txt
RESET_WHITELIST=<true|false>
SERVER_PORT=80 # Port that the gateway will listen for connections

N_CONNECTION_TRIES=15 # Maximum amount of retries when attempting to find the dependency services at startup
SLEEP_CONNECTION_TRIES=1000 # Delay between each retry

BACKEND_URL=<url> # URL of the backend service to proxyfy

POSTGRES_DB=<> # Name of the postgre database
POSTGRES_USER=<> # Name of the postgres user
POSTGRES_PASSWORD=<> # Password of the postgres user
POSTGRES_HOST=<> # Postgres hostname
POSTGRES_PORT=5432 # Postgres port
```

Furthermore, for the test, you need to add the following environment variables:

```
TEST_MNEMONIC=<string> # String used to generate the testing address's keys. The respective address should be inclued in the whitelist.txt file.
```

### Docker

To deploy on the local machine using `docker-compose`, execute the command:
```
docker-compose up --build
```

### Kubernetes

To deploy in a `kubernetes` cluster, first you need to deploy the `whitelist.txt` and `.env` files through the following commands:

```
kubectl create configmap whitelist --from-file whitelist.txt
kubectl create secret generic login-env --from-env-file=.env
```

NOTE: the `.env` must not contain any type of quotes, otherwise it will be wrongly parsed by kubectl.

Then, you need to push the image into a repository and be sure that the cluster can pull images from that repository.

Before deploying the gateway service, you need to deploy the backend service to proxyfy.

Finally, to deploy the gateway service, execute the command:
```
kubectl apply -f gateway.yml
```
