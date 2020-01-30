const nodemailer = require('nodemailer')
const smtpTransport = require('nodemailer-smtp-transport')

module.exports = function (options) {
  const trn = smtpTransport(options.connstring)
  const transporter = nodemailer.createTransport(trn)

  console.log('SMTP verify: ' + options.connstring)
  transporter.verify()
    .then(() => {
      console.log('SMTP ready ...')
    })
    .catch(err => {
      console.error(err)
    })

  return function ({ from, to, subject, body, html }) {
    const data = {
      from,
      to,
      subject,
      text: body
    }
    console.log(data)
    return transporter.sendMail(data)
      .then(res => {
        console.log(res)
        return res
      })
      .catch(err => {
        console.error(err)
      })
  }
}
