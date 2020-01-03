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
  //   'set-username',
  //   [ooth.requireLogged],
  //   async ({ username }, userId, locale) => {
  //     if (typeof username !== 'string') {
  //       throw new Error(__('set_username.invalid_username', null, locale))
  //     }
  //
  //     testValue('username', username, locale)
  //
  //     const existingUser = await ooth.getUserByUniqueField('username', username)
  //
  //     if (existingUser) {
  //       throw new Error(__('set_username.username_taken', null, locale))
  //     }
  //
  //     await ooth.updateUser(name, userId!, {
  //       username,
  //     })
  //
  //     return {
  //       message: __('set_username.username_updated', null, locale),
  //     }
  //   },
  // )

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
    'validationCode',
    [ooth.requireNotLogged],
    async ({ phone }, _userId, locale) => {
      if (typeof phone !== 'number') {
        throw new Error('validation.invalid_phone')
      }
      testValue('phone', phone, locale)

      const code = Codes.generate(phone)
      SMS.send('verify', code)

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

  // ooth.registerMethod(
  //   name,
  //   'forgot-password',
  //   [ooth.requireNotLogged],
  //   async ({ username }: any, _userId: string | undefined, locale: string): Promise<Result> => {
  //     if (!username || typeof username !== 'string') {
  //       throw new Error(__('forgot_password.invalid_username', null, locale))
  //     }
  //
  //     let user = await ooth.getUserByUniqueField('username', username)
  //     if (!user) {
  //       user = await ooth.getUserByUniqueField('email', username)
  //     }
  //
  //     if (!user) {
  //       throw new Error(__('forgot_password.no_user', null, locale))
  //     }
  //
  //     const email = ooth.getUniqueField(user, 'email')
  //
  //     const passwordResetToken = randomToken()
  //
  //     await ooth.updateUser(name, user._id, {
  //       email,
  //       passwordResetToken: await hash(passwordResetToken, SALT_ROUNDS),
  //       passwordResetTokenExpiresAt: new Date(Date.now() + HOUR),
  //     })
  //
  //     await ooth.emit(name, 'forgot-password', {
  //       email,
  //       passwordResetToken,
  //       _id: user._id,
  //     })
  //
  //     return {
  //       message: __('forgot_password.token_generated', null, locale),
  //     }
  //   },
  // )

  // ooth.registerMethod(
  //   name,
  //   'reset-password',
  //   [ooth.requireNotLogged],
  //   async ({ userId, token, newPassword }: any, _userId: string | undefined, locale: string): Promise<Result> => {
  //     if (!userId) {
  //       throw new Error(__('reset_password.no_user_id', null, locale))
  //     }
  //
  //     if (!token) {
  //       throw new Error(__('reset_password.no_token', null, locale))
  //     }
  //
  //     if (!newPassword || typeof newPassword !== 'string') {
  //       throw new Error(__('reset_password.invalid_password', null, locale))
  //     }
  //
  //     testValue('password', newPassword, locale)
  //
  //     const user = await ooth.getUserById(userId)
  //
  //     if (!user) {
  //       throw new Error('User does not exist.')
  //     }
  //
  //     const strategyValues = user[name] as StrategyValues
  //
  //     if (!strategyValues || !strategyValues.passwordResetToken) {
  //       throw new Error(__('reset_password.no_reset_token', null, locale))
  //     }
  //
  //     if (!(await compare(token, strategyValues.passwordResetToken))) {
  //       throw new Error(__('reset_password.invalid_token', null, locale))
  //     }
  //
  //     if (!strategyValues.passwordResetTokenExpiresAt) {
  //       throw new Error(__('reset_password.no_expiry', null, locale))
  //     }
  //
  //     if (new Date() >= strategyValues.passwordResetTokenExpiresAt) {
  //       throw new Error(__('reset_password.expired_token', null, locale))
  //     }
  //
  //     await ooth.updateUser(name, user._id, {
  //       passwordResetToken: null,
  //       password: await hash(newPassword, SALT_ROUNDS),
  //     })
  //
  //     await ooth.emit(name, 'reset-password', {
  //       _id: user._id,
  //       email: strategyValues.email,
  //     })
  //
  //     return {
  //       message: __('reset_password.password_reset', null, locale),
  //     }
  //   },
  // )

  // ooth.registerMethod(
  //   name,
  //   'change-password',
  //   [ooth.requireLogged],
  //   async ({ password, newPassword }: any, userId: string | undefined, locale: string): Promise<Result> => {
  //     if (typeof password !== 'string') {
  //       throw new Error(__('change_password.invalid_password', null, locale))
  //     }
  //
  //     testValue('password', newPassword, locale)
  //
  //     const user = await ooth.getUserById(userId!)
  //
  //     const strategyValues = user![name] as StrategyValues
  //
  //     if ((password || (strategyValues && strategyValues.password)) && !(await compare(password, strategyValues.password))) {
  //       throw new Error(__('change_password.invalid_password', null, locale))
  //     }
  //
  //     await ooth.updateUser(name, userId!, {
  //       passwordResetToken: null,
  //       password: await hash(newPassword, SALT_ROUNDS),
  //     })
  //
  //     await ooth.emit(name, 'change-password', {
  //       _id: userId!,
  //       email: strategyValues && strategyValues.email,
  //     })
  //
  //     return {
  //       message: __('change_password.password_changed', null, locale),
  //     }
  //   },
  // )
}
