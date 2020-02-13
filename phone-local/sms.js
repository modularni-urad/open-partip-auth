const axios = require('axios')
const SEND_URL = process.env.SMS_SEND_URL

module.exports = (options) => {
  //
  const CONTENTS = `Potvrzovaci kod pro ${options.web} je: `

  return {
    send: (phone, code) => {
      const msg = CONTENTS + code
      process.env.NODE_ENV !== 'production' && console.log(`code: ${code}`)
      return axios.post(`${SEND_URL}/?num=${phone}&mess=${msg}`)
    }
  }
}
