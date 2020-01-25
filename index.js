require('dotenv').config()
const express = require('express')
const { Ooth } = require('ooth')
const { OothMongo } = require('ooth-mongo')
const oothLocal = require('./phone-local')
const oothUser = require('ooth-user').default
const emailer = require('ooth-local-emailer').default
const oothJwt = require('ooth-jwt').default
const morgan = require('morgan')
const cors = require('cors')
const mail = require('./mail')
const czStrings = require('./cs.js')
const { MongoClient } = require('mongodb')

async function start () {
  try {
    const app = express()
    app.use(morgan('dev'))
    const corsMiddleware = cors({
      origin: process.env.ORIGIN_URL,
      credentials: true,
      preflightContinue: false
    })
    app.use(corsMiddleware)
    app.options(corsMiddleware)

    const client = await MongoClient.connect(process.env.MONGO_URL, {
      useUnifiedTopology: true
    })
    const db = client.db(process.env.MONGO_DBNAME)

    const oothMongo = new OothMongo(db)
    const ooth = new Ooth({
      app,
      backend: oothMongo,
      standalone: true
    })

    oothLocal({ ooth })

    const verifyURL = `${process.env.MAIL_URL}/local/verify-email?token={verification-token}&userId={user-id}`
    emailer({
      ooth,
      from: process.env.MAIL_FROM,
      siteName: process.env.MAIL_SITE_NAME,
      translations: { cs: czStrings },
      defaultLanguage: 'cs',
      urls: { verifyEmail: verifyURL },
      sendMail: mail({
        connstring: process.env.SMTP_CONN
      })
    })
    oothUser({ ooth })
    oothJwt({ ooth, sharedSecret: process.env.SHARED_SECRET, tokenLocation: 'header' })

    app.listen(process.env.PORT, function () {
      console.info(`Ooth started on port ${process.env.PORT}`)
    })
  } catch (e) {
    console.error(e)
  }
}

start()
