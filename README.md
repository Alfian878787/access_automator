# access_automator

A Ruby script to automate the process of granting/revoking SSH access to a specific group of EC2 servers.

For security and auditing purposes a new user account is added/removed from a server rather than use the native ec2 user.

The group is defined by EC2 tags using key 'Type'. EC2 instances are connected to via private IP.

## ADMIN ASSUMPTIONS:

Whoever (or whatever) is running this script needs to meet the following conditions to run this:

1) Root access to the group of servers in question
2) Access to administer AWS via access key
3) Connectivity to the servers via private IP
4) Public key present on the servers for password-less ssh

## Configuring

The is an option to use a particular SSH private key instead of the default (id_rsa or id_dsa). In order to use this create config.json in this directory with the following contents:

```
{
    "private_key": "myawesomekey"
}
```

Where "myawesomekey" needs to be a private key in ~/.ssh for this to work.

## Running

The script is run on Docker for your convenience. Just build the image first:

```
docker build -t access_automator .
```

The container needs access to two directories for authentication: ~/.aws and ~/.ssh. Bind these directories to run the script:

```
docker run -it --rm -v ~/.ssh:/root/.ssh -v ~/.aws:/root/.aws access_automator
```

## Examples

To grant Tony access to app-servers:

```
docker run -it --rm -v ~/.ssh:/root/.ssh -v ~/.aws:/root/.aws access_automator grant tony app-servers
```

To revoke Tony's access from app-servers:

```
docker run -it --rm -v ~/.ssh:/root/.ssh -v ~/.aws:/root/.aws access_automator revoke tony app-servers
```
