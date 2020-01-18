# open-partip-auth

AUTH microservice for storing identities based on phone number.
Only phone number, email, password are stored.
API provides routes for:
- register
- login
- change-password

## SETTINGS

Only thru ENVIRONMENT VARIABLES. Sample .env file (we are using [dotenv](https://github.com/motdotla/dotenv)) can look like this:

```
PORT=30011
MONGO_URL=mongodb://localhost:27017/ooth
ORIGIN_URL=http://localhost:8080
MAIL_FROM=info@example.com
MAIL_SITE_NAME=My great site
MAIL_URL=http://localhost:3000
SMTP_CONN=smtps://gandalf%40gmail.com:secretWhisper@smtp.gmail.com
SHARED_SECRET=string_for_securing_JWT_tokens
SESSION_SECRET=string_for_securing
```

You can set the variables in your [docker-compose.yml](https://docs.docker.com/compose/environment-variables/) or whatever deployment way want.
