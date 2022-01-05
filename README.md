# Description

This project is a [NestJS](https://docs.nestjs.com/) API project.

If you run the project, you will create a Rest API with two different types of authorization methods.

## JWT secret authorization

First, it is important to define the `AUTH_JWT_SECRET` secret key on the .env file. As a sugestion, you can easily generate a key on [keygen.io](https://keygen.io/) "SHA 256-bit Key" section.

Then, you will be able to generate a token by calling the `POST /token` endpoint. The _username_, _email_, and _name_ fields may be any value you decide.

At last, to consume the `/jwt-secret/hello` endpoint you will need to set the Authorization header with a Bearer token generated on the previous step.

For example:

* Generating the token

* Calling the `/jwt-secret/hello` endpoint

## Cognito client credentials token

First, you need to create a Cognito User Pool with a Cognito Domain. It is important to map the recently create Cognito Pool ID on the `COGNITO_POOL_ID` secret key on the .env file of the project.

Set in the App Integration a resource server with the server identifier as `http://localhost:3001` and define the custom scopes you want.

Create an App Client with the following characteristics:

* App type: Other
* Client secret: Generate a client secret. This is used to automatically generate a client secret for the app client
* Identity Providers: Cognito user pool
* [OAuth 2.0 Grant Types](https://aws.amazon.com/blogs/mobile/understanding-amazon-cognito-user-pool-oauth-2-0-grants/): Client credentials

The rest of the configuration is up to you.

Then, you can use the AWS [POST /oauth/token](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html) endpoint to generate a valid Cognito token. To have in mind, you will need the Cognito Domain created on the first step, and the client_id and client_secret of the recently created App Client.



Finally, you can consume the `/client-credentials/hello` endpoint by setting the Basic Authorization header with the token generated on the previous step.

It is necessary to read all the `//TODO` comments and solve them.

# Installation

```bash
$ npm install
```

# Running the app

```bash
# development
$ npm run start

# watch mode
$ npm run start:dev

# production mode
$ npm run start:prod
```



# Stay in touch

- Author - [Sergio Yepes](https://github.com/sergioyepes21)
- LinkedIn - [Sergio Yepes](https://www.linkedin.com/in/sergio-andr%C3%A9s-yepes-joven-41405b174)

# License

Nest is [MIT licensed](LICENSE).
