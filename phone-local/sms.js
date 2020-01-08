
module.exports = (options) => {
  //
  const CONTENTS = `Potvrzovaci kod pro ${options.web} je: `

  return {
    send: (code) => {
      const msg = CONTENTS + code
      console.log(msg)
    }
  }
}
