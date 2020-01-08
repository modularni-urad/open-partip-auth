const { compare, hash } = require('bcrypt')
const { randomBytes } = require('crypto')
const { Request } = require('express')
const { FullRequest, Ooth, StrategyValues } = require('ooth')
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

module.exports = function ({ name = 'local', ooth, defaultLanguage, translations, validators }) {
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

  // ooth.registerMethod(
  //   name,
  //   'set-email',
  //   [ooth.requireLogged],
  //   async ({ email }: any, userId: string | undefined, locale: string): Promise<Result> => {
  //     if (typeof email !== 'string') {
  //       throw new Error(__('set_email.invalid_email', null, locale))
  //     }
  //
  //     testValue('email', email, locale)
  //
  //     const existingUser = await ooth.getUserByUniqueField('email', email)
  //     if (existingUser && existingUser._id !== userId!) {
  //       throw new Error(__('set_email.email_already_registered', null, locale))
  //     }
  //
  //     const verificationToken = randomToken()
  //
  //     await ooth.updateUser(name, userId!, {
  //       email,
  //       verificationToken: await hash(verificationToken, SALT_ROUNDS),
  //       verificationTokenExpiresAt: new Date(Date.now() + HOUR),
  //     })
  //
  //     await ooth.emit(name, 'set-email', {
  //       email,
  //       verificationToken,
  //       _id: userId!,
  //     })
  //
  //     return {
  //       message: __('set_email.email_updated', null, locale),
  //     }
  //   },
  // )

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
      sms.send(code)

      return { message: 'ok' }
    }
  )

  // ooth.registerMethod(
  //   name,
  //   'generate-verification-token',
  //   [ooth.requireRegisteredWith(name)],
  //   async (_: any, userId: string | undefined, locale: string): Promise<Result> => {
  //     const verificationToken = randomToken()
  //
  //     const user = await ooth.getUserById(userId!)
  //
  //     if (!user![name] || !(user![name] as StrategyValues).email) {
  //       throw new Error(__('generate_verification_token.no_email', null, locale))
  //     }
  //
  //     await ooth.updateUser(name, userId!, {
  //       verificationToken: await hash(verificationToken, SALT_ROUNDS),
  //       verificationTokenExpiresAt: new Date(Date.now() + HOUR),
  //     })
  //
  //     await ooth.emit(name, 'generate-verification-token', {
  //       verificationToken,
  //       _id: userId!,
  //       email: (user![name] as StrategyValues).email,
  //     })
  //
  //     return {
  //       message: __('generate_verification_token.token_generated', null, locale),
  //     }
  //   },
  // )

  // ooth.registerMethod(
  //   name,
  //   'verify',
  //   [],
  //   async ({ userId, token }, _userId: string | undefined, locale: string): Promise<Result> => {
  //     if (!userId) {
  //       throw new Error(__('verify.no_user_id', null, locale))
  //     }
  //
  //     if (!token) {
  //       throw new Error(__('verify.token_generated', null, locale))
  //     }
  //
  //     const user = await ooth.getUserById(userId)
  //     if (!user) {
  //       throw new Error(__('verify.no_user', null, locale))
  //     }
  //
  //     const strategyValues: StrategyValues = user[name] as StrategyValues
  //
  //     if (!strategyValues || !strategyValues.email) {
  //       // No email to verify, but let's not leak this information
  //       throw new Error(__('verify.no_email', null, locale))
  //     }
  //
  //     if (!(await compare(token, strategyValues.verificationToken))) {
  //       throw new Error(__('verify.invalid_token', null, locale))
  //     }
  //
  //     if (!strategyValues.verificationTokenExpiresAt) {
  //       throw new Error(__('verify.no_expiry', null, locale))
  //     }
  //
  //     if (new Date() >= strategyValues.verificationTokenExpiresAt) {
  //       throw new Error(__('verify.expired_token', null, locale))
  //     }
  //
  //     await ooth.updateUser(name, user._id, {
  //       verified: true,
  //       verificationToken: null,
  //     })
  //
  //     const newUser = await ooth.getUserById(user._id)
  //
  //     await ooth.emit(name, 'verify', {
  //       _id: newUser._id,
  //       email: (newUser[name] as StrategyValues).email,
  //     })
  //
  //     return {
  //       message: __('verify.verified', null, locale),
  //     }
  //   },
  // )

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

      await ooth.emit(name, 'change-password', {
        _id: existingUser._id, phone
      })

      return { message: 'change_password.password_changed' }
    }
  )
}
