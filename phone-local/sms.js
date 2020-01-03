
module.exports = (options) => {
  //
  const CONTENTS = {
    verify: `Potvrzovaci kod pro registraci na ${options.web} je: `
  }

  return {
    send: (typ, code) => {
      const msg = CONTENTS[typ] + code
      console.log(msg)
    }
  }
}
