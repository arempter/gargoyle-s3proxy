[![Build Status](https://travis-ci.org/arempter/gargoyle-s3proxy.svg?branch=master)](https://travis-ci.org/arempter/gargoyle-s3proxy)
[![codecov.io](http://codecov.io/github/arempter/gargoyle-s3proxy/coverage.svg?branch=master)](https://codecov.io/gh/arempter/gargoyle-s3proxy?branch=master)
[![](https://images.microbadger.com/badges/image/arempter/gargoyle-s3proxy:master.svg)](https://microbadger.com/images/arempter/gargoyle-s3proxy:master)
[![](https://images.microbadger.com/badges/version/arempter/gargoyle-s3proxy:master.svg)](https://microbadger.com/images/arempter/gargoyle-s3proxy:master)

# project moved to [ing airlock](https://github.com/ing-bank/airlock)

# Gargoyle S3Proxy

gargoyle-s3proxy acts as a security layer between s3 user (eg. application using aws sdk) and s3 backend (eg. ceph RadosGW).

## What do you need

To get started with Gargoyle you only need a few applications set up:

- Docker
- AWS CLI
- [Optional for coding] SBT

We've added a small description on how to setup the AWS CLI [here](#setting-up-aws-cli).

## How to run
1. To test the proxy (both live and integration tests), we need all dependencies to be running. For this we use a `docker-compose.yml` which defines all dependencies, run it using:

        docker-compose up

2. Before we can run our proxy, we have to specify the configuration for Apache Ranger. Ranger can be configured by creating a file called `ranger-s3-security.xml` on the classpath.
    There are 2 places you can put it:
    
    1. `REPO_ROOTDIR/src/main/resources/ranger-s3-security.xml`
    2. `/etc/gargoyle/ranger-s3-security.xml`
    
    An example of this file can be found [here](./src/it/resources/ranger-s3-security.xml). 
    No modification to this is needed if you run this project with the accompanying docker containers.

3. When all is runnning we can start the proxy:

        sbt run

> for windows docker runs on different it so you need to:
> set environmental variables:
> * GARGOYLE_STS_HOST
> * GARGOYLE_STORAGE_S3_HOST
> * GARGOYLE_KEYCLOAK_TOKEN_URL
> * change GARGOYLE_KEYCLOAK_URL in the docker-compose.yml
> * change the ranger.plugin.s3.policy.rest.url in ranger-s3-security.xml


### Proxy as docker image

When proxy is started as docker image, the ranger-s3-security.xml file can be added in the following way:

        docker run -d -v /host/dir/with/xmls:/etc/gargoyle -p 8010:8010 gragoyle-s3proxy

## Getting Started

> This guide assumes you're using the default docker containers provided, see: [How to run](#how-to-run)

Now you've got everything running, you may wonder: what now? This section we'll describe a basic flow on how to use 
Gargoyle to perform operations in S3. You may refer to the [What is Gargoyle?](./docs/What_is_gargoyle.md) document
before diving in here. That will introduce you to the various components used.

1. Authorise with keycloak to request a `keycloak token`:

        curl -s 
             -d 'client_id=sts-gargoyle' 
             -d 'username=testuser' 
             -d 'password=password' 
             -d 'grant_type=password' 
             'http://localhost:8080/auth/realms/auth-gargoyle/protocol/openid-connect/token'

    Search for the field `access_token` which contains your token.
    
2. Retrieve your short term `session credentials` from the STS service:

        aws sts get-session-token --endpoint-url http://localhost:12345 --token-code YOUR_KEYCLOAK_TOKEN_HERE
   
   This should give you an `accessKeyId`, `secretAccessKey`, `sessionToken` and `expirationDate`.
   
3. Setup your local environment to use the credentials received from STS. You can do this in 2 ways.

    1. Set them in your environment variables:
        
            export AWS_ACCESS_KEY_ID=YOUR_ACCESSKEY
            export AWS_SECRET_ACCESS_KEY=YOUR_SECRETKEY
            export AWS_SESSION_TOKEN=YOUR_SESSIONTOKEN
            
    2. Set them in your `~/.aws/config` file. See the [Setting up AWS CLI](#setting-up-aws-cli) guide on how to do this.
   
    > NOTE: This session expires at the expiration date specified by the STS service. You'll need to repeat these steps
    > everytime your session expires.
 
4. Technically you're now able to use the aws cli to perform any commands through Gargoyle
   to S3. Gargoyle automatically creates the user on Ceph for you. One thing it cannot do though, is make this user an 
   admin/system user. Because of this, users on Ceph are not allowed to perform actions on other users' buckets.
   
   Since Ranger is in place to handle authorisation, all users on Ceph can be allowed to do everything.
   
   In order to allow a user on Ceph to access other buckets, we currently rely on them to be `system` users. Gargoyle
   will automatically create the user on Ceph for you, but setting them to be `system` users still needs to be done
   manually using the following steps:
   
   1. Find the ID of the docker Ceph container:
   
            docker ps
            
   2. Open a shell in the Ceph container:
   
            docker exec -it YOUR_CEPH_CONTAINER_ID bash
            
   3. Set the `testuser` to be a `system` user:
   
            radosgw-admin user modify --uid testuser --system
            
5. Go nuts with the default bucket called `demobucket` that exists on Ceph already:

        aws s3api list-objects --bucket demobucket
        aws s3api put-object --bucket demobucket --key SOME_FILE
        
   **!BOOM!** What happened?!
   
   Well, your policy in Ranger only allows you to read objects from the `demobucket`. So we'll need to allow a write as
   well. 
   
   1. Go to Ranger on [http://localhost:6080](http://localhost:6080) and login with `admin:admin`. 
   2. Go to the `testservice` under the S3 header.
   3. Edit the one existing policy. You'll have to allow the `testuser` to write, but also don't forget to remove the 
   deny condition!
   4. Save the policy at the bottom of the page.
   
   Now it'll take maximum 30 seconds for this policy to sync to the Proxy. Then you should be able to retry:
   
        aws s3api put-object --bucket demobucket --key SOME_FILE
        aws s3api list-objects --bucket demobucket
        aws s3api get-object --bucket demobucket --key SOME_FILE SOME_TARGET_FILE


## Architecture
![alt text](./docs/img/architecture.png)

Dependencies:
* [Keycloak](https://www.keycloak.org/) for MFA authentication of users.
* [STS Service](https://github.com/kr7ysztof/gargoyle-sts) to provide authentication and short term access to resources on S3.
* [Ranger](https://ranger.apache.org/) to manage authorisation to resources on S3.
The Apache Ranger docker images are created from this repo: https://github.com/nielsdenissen/ranger-for-gargoyle.git
* S3 Backend (Current setup contains Ceph image with RadosGW)

A more in-depth discussion of the architecture and interaction of various components can be found here: [What is Gargoyle?](./docs/What_is_gargoyle.md)


## Docker Ceph settings

In order to enable debug logging on Ceph RadosGW:

1. Edit  /etc/ceph/ceph.conf and add following lines, under [global] section
```
debug rgw = 20
debug civetweb = 20
```

2. Restart rgw process (either docker stop <ceph/daemon rgw> or whole ceph/demo)

## Lineage to Atlas

Currently it is possible to create lineage based on incoming request to proxy server. It is however disabled by
default (preview feature). To enable lineage shipment to Atlas, following setting has to be added to application.conf:

```
gargoyle {
     atlas {
        enabled = true
     }
}
``` 

As alternative environment value `GARGOYLE_ATLAS_ENABLED` should be set to true. 

Lineage is done according following model
 
![alt text](./docs/img/atlas_model.jpg)

To check lineage that has been created, login to Atlas web UI console, [default url](http://localhost:21000) with
admin user and password 


## Setting Up AWS CLI

It is possible to set up the AWS command-line tools for working with Ceph RadosGW and Gargoyle. Following are instructions
to set this up using `virtualenv_wrapper` or [Anaconda](https://www.anaconda.com/).

1. Create an environment for this work:

    a. **virtualenv_wrapper**

       % mkvirtualenv -p python3 gargoyle
       
    b. **Anaconda**

       % conda create -n gargoyle python=3
       % source activate gargoyle

2. Install the AWS command-line tools and the endpoint plugin:

       % pip install awscli awscli-plugin-endpoint

3. Configure profiles and credentials for working with Gargoyle or the RadosGW directly (more info can be found in the
[aws documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-config-files.html)):

       % mkdir -p ~/.aws
       
       % cat >> ~/.aws/credentials << EOF
       [radosgw]
       aws_access_key_id = accesskey
       aws_secret_access_key = secretkey

       [gargoyle]
       aws_access_key_id = YOUR_ACCESSKEY
       aws_secret_access_key = YOUR_SECRETKEY
       aws_session_token = YOUR_SESSIONTOKEN
       EOF
       
       % cat >> ~/.aws/config << EOF
       [plugins]
       endpoint = awscli_plugin_endpoint

       [profile gargoyle]
       output = json
       region = localhost
       s3 =
           endpoint_url = http://localhost:8987/
       s3api =
           endpoint_url = http://localhost:8987/
       sts =
           endpoint_url = http://localhost:12345/

       [profile radosgw]
       output = json
       region = localhost
       s3 =
           endpoint_url = http://localhost:8010/
       s3api =
           endpoint_url = http://localhost:8010/
       EOF

4. Configure the default profile and reactivate the virtual environment:

    a. **virtualenv_wrapper**
    
       % cat >> ${WORKON_HOME:-$HOME/.virtualenvs}/gargoyle/bin/postactivate << EOF
       AWS_DEFAULT_PROFILE=gargoyle
       export AWS_DEFAULT_PROFILE
       EOF
       
       % cat >> ${WORKON_HOME:-$HOME/.virtualenvs}/gargoyle/bin/predeactivate << EOF
       unset AWS_DEFAULT_PROFILE
       EOF
       
       % deactivate
       
       % workon gargoyle

    b. **Anaconda**
    
       % cat >> /YOUR_CONDA_HOME/envs/gargoyle/etc/conda/deactivate.d/aws.sh << EOF
       AWS_DEFAULT_PROFILE=gargoyle
       export AWS_DEFAULT_PROFILE
       EOF
       
       % cat >> /YOUR_CONDA_HOME/envs/gargoyle/etc/conda/activate.d/aws.sh << EOF
       unset AWS_DEFAULT_PROFILE
       EOF
       
       % source deactivate
       
       % source activate gargoyle

By default S3 and STS commands will now be issued against the proxy service. For example:

    % aws s3 ls

Commands can also be issued against the underlying RadosGW service:

    % aws --profile radosgw s3 ls

The default profile can also be switched by modifying the `AWS_DEFAULT_PROFILE` environment variable.
