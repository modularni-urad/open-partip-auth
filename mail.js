const nodemailer = require('nodemailer')
const smtpTransport = require('nodemailer-smtp-transport')

module.exports = function (options) {
  const transporter = nodemailer.createTransport(smtpTransport(options.connstring))
  return function ({ from, to, subject, body, html }) {
    return transporter.sendMail({
      from,
      to,
      subject,
      text: body
    }).catch(err => {
      console.error(err)
    })
  }
}
