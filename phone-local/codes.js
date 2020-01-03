const phoneToken = require('generate-sms-verification-code')

const DB = {}

module.exports = {
  generate: (phone) => {
    const token = phoneToken(8, { type: 'number' })
    DB[phone] = token
    return token
  },
  validate: (phone, token) => {
    const valid = DB[phone] === token
    valid && delete DB[phone]
    return valid
  }
}
