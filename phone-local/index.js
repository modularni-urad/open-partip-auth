const { compare, hash } = require('bcrypt')
const { randomBytes } = require('crypto')
// const { Request } = require('express')
// const { FullRequest, Ooth, StrategyValues } = require('ooth')
const { Strategy } = require('passport-local')
const { callbackify } = require('util')
const Codes = require('./codes')
const SMS = require('./sms')

const SALT_ROUNDS = 12
const HOUR = 1000 * 60 * 60

const DEFAULT_VALIDATORS = {
  phone: {
    regex: /^[0-9]{9}$/,
    error: 'validators.invalid_phone'
  },
  password: {
    test: (password) =>
      /\d/.test(password) && /[a-z]/.test(password) && /[A-Z]/.test(password) && /.{6,}/.test(password),
    error: 'validators.invalid_password'
  },
  email: {
    regex: /^.+@.+$/,
    error: 'validators.invalid_email'
  }
}

function randomToken () {
  return randomBytes(43).toString('hex')
}

module.exports = function ({ name = 'local', ooth, defaultLanguage, validators }) {
  const actualValidators = { ...DEFAULT_VALIDATORS, ...validators }
  const sms = SMS({ web: 'info.taborcz.eu' })

  function testValue (key, value, language) {
    const validator = actualValidators[key]
    if (validator.regex) {
      if (!validator.regex.test(value)) {
        throw new Error(validator.error)
      }
    } else {
      if (!validator.test(value)) {
        throw new Error(validator.error)
      }
    }
  }

  ooth.registerUniqueField(name, 'phone', 'phone')
  ooth.registerUniqueField(name, 'email', 'email')
  ooth.registerProfileFields(name, 'phone', 'email', 'verified')

  ooth.registerPrimaryAuth(
    name,
    'login',
    [ooth.requireNotLogged],
    new Strategy(
      {
        usernameField: 'username',
        passwordField: 'password',
        passReqToCallback: true
      },
      callbackify(async (req, username, password) => {
        const err = 'login.invalid_credentials'

        let user = await ooth.getUserByUniqueField('phone', Number(username))
        if (!user) {
          user = await ooth.getUserByUniqueField('email', username)
        }

        if (!user || !user[name]) {
          throw new Error(err)
        }

        if (!(await compare(password, (user[name]).password))) {
          throw new Error(err)
        }

        return user._id
      })
    )
  )

  ooth.app.put('/local/set-email', async (req, res) => {
    try {
      const email = req.query.email
      const uid = req.query.uid
      if (typeof email !== 'string') {
        throw new Error('set_email.invalid_email')
      }

      testValue('email', email, 'en')

      const existingUser = await ooth.getUserByUniqueField('email', email)
      if (existingUser && existingUser._id !== uid) {
        throw new Error('set_email.email_already_registered')
      }

      const verificationToken = randomToken()

      await ooth.updateUser(name, uid, {
        email4verify: email,
        verificationToken: await hash(verificationToken, SALT_ROUNDS),
        verificationTokenExpiresAt: new Date(Date.now() + HOUR)
      })

      await ooth.emit(name, 'set-email', {
        email,
        verificationToken,
        _id: uid
      })

      res.json({ message: 'set_email.email_updated' })
    } catch (err) {
      res.status(400).json(err.message)
    }
  })

  ooth.registerMethod(
    name,
    'register',
    [ooth.requireNotLogged],
    async ({ phone, email, password, validcode }, _userId, locale) => {
      if (typeof phone !== 'number') {
        throw new Error('validation.invalid_phone')
      }
      if (typeof email !== 'string') {
        throw new Error('register.invalid_email')
      }
      if (typeof password !== 'string') {
        throw new Error('register.invalid_password')
      }
      if (!Codes.validate(phone, validcode)) {
        throw new Error('register.invalid_validation_code')
      }

      testValue('password', password, locale)

      const existingUser = await ooth.getUserByUniqueField('phone', phone)
      if (existingUser) {
        throw new Error('register.phone_already_registered')
      }

      const verificationToken = randomToken()

      const _id = await ooth.insertUser(name, {
        phone,
        email,
        password: await hash(password, SALT_ROUNDS),
        verificationToken: await hash(verificationToken, SALT_ROUNDS),
        verificationTokenExpiresAt: new Date(Date.now() + HOUR)
      })

      await ooth.emit(name, 'register', {
        _id,
        phone,
        email,
        verificationToken
      })

      return { message: 'register.registered' }
    }
  )

  ooth.registerMethod(
    name,
    'validationcode',
    [ooth.requireNotLogged],
    async ({ phone }, _userId, locale) => {
      if (typeof phone !== 'number') {
        throw new Error('validation.invalid_phone')
      }
      testValue('phone', phone, locale)

      const code = Codes.generate(phone)
      await sms.send(phone, code)

      return { message: 'ok' }
    }
  )

  ooth.app.get('/local/verify-email', async (req, res) => {
    try {
      if (!req.query || !req.query.userId) {
        throw new Error('verify.no_user_id')
      }

      if (!req.query || !req.query.token) {
        throw new Error('verify.token_generated')
      }

      const user = await ooth.getUserById(req.query.userId)
      if (!user) {
        throw new Error('verify.no_user')
      }

      const strategyValues = user[name]

      if (!strategyValues || !strategyValues.email4verify) {
        // No email to verify, but let's not leak this information
        throw new Error('verify.no_email')
      }

      if (!strategyValues.verificationToken ||
          !(await compare(req.query.token, strategyValues.verificationToken))) {
        throw new Error('verify.invalid_token')
      }

      if (!strategyValues.verificationTokenExpiresAt) {
        throw new Error('verify.no_expiry')
      }

      if (new Date() >= strategyValues.verificationTokenExpiresAt) {
        throw new Error('verify.expired_token')
      }

      await ooth.updateUser(name, user._id, {
        email: strategyValues.email4verify,
        verified: true,
        verificationToken: null,
        email4verify: null
      })

      const newUser = await ooth.getUserById(user._id)

      await ooth.emit(name, 'verify', {
        _id: newUser._id,
        email: (newUser[name]).email
      })
      res.json({ message: 'verify.verified' })
    } catch (err) {
      res.status(400).json(err.message)
    }
  })

  ooth.registerMethod(
    name,
    'change-password',
    [ooth.requireNotLogged],
    async ({ phone, password, validcode }, userId) => {
      if (typeof password !== 'string') {
        throw new Error('change_password.invalid_password')
      }
      if (!Codes.validate(phone, validcode)) {
        throw new Error('register.invalid_validation_code')
      }

      testValue('password', password)

      const existingUser = await ooth.getUserByUniqueField('phone', phone)
      if (!existingUser) {
        throw new Error('register.invalid_phone')
      }

      await ooth.updateUser(name, existingUser._id, {
        password: await hash(password, SALT_ROUNDS)
      })

      return { message: 'change_password.password_changed' }
    }
  )
}
