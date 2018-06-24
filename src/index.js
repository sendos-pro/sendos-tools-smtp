/**
 * @title sendosToolsSmtpCheck
 */

 import dns from "dns"
 import net from "net"
 import os from "os"
 import randomstring from "randomstring"

 const resolveMx = hostname => {
  return new Promise((resolve, reject) => {
    dns.resolveMx(hostname, (err, val) => {
      if (err) {
        return reject(err)
      }
      resolve(val)
    })
  })
}

const isMail = domainOrEmail => {
  const regex = /^(([^<>()\[\]\\.,:\s@"]+(\.[^<>()\[\]\\.,:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
  const isValidPattern = regex.test(domainOrEmail)
  return isValidPattern
}

/**
 * Email address validation and SMTP verification API.

 * @param {Object} config - The email address you want to validate.
 * @param {string} config.domainOrEmail - The email address you want to validate.
 * @param {string} [config.mailFrom] - The email address used for the mail from during SMTP mailbox validation.
 * @param {string[]} [config.invalidMailboxKeywords] - Keywords you want to void, i.e. noemail, noreply etc.
 * @param {number} [config.timeout] - The timeout parameter for SMTP mailbox validation.
 * @returns {instance}
 * @class sendosToolsSmtpCheck
 */
 class sendosToolsSmtpCheck {
  constructor({ domainOrEmail, timeout }) {
    let domain = domainOrEmail.toLowerCase()

    if (isMail(domain)) {
      domain = domain.split("@")[1]
    }

    this.state = {
      // result
      result: false,

      // args
      domain,
      timeout: timeout || 10000,

      // results
      rDnsMismatch: {
        result: false,
        data: false
      },
      validHostname: {
        result: false,
        data: false
      },
      bannerCheck: {
        result: false,
        data: false
      },
      tls: {
        result: false
      },
      openRelay: {
        result: false
      },

      // helpers
      mxRecords: [],
      smtpMessages: [],
      errors: []
    }
  }

  /**
   * Check pattern
   */
   static resolvePattern(domain) {
    const regex = /^[a-zA-Z0-9_-]+\.[.a-zA-Z0-9_-]+$/
    return regex.test(domain)
  }

  // private instance method
  _resolvePattern(domain) {
    return sendosToolsSmtpCheck.resolvePattern(domain)
  }

  /**
   * rDnsMismatch
   */
   static rDnsMismatch(domain) {
    return domain
  }

  // private instance method
  _rDnsMismatch(domain) {
    return sendosToolsSmtpCheck.rDnsMismatch(domain)
  }

  /**
   * validHostname
   */
   static validHostname(domain) {
    return domain
  }

  // private instance method
  _validHostname(domain) {
    return sendosToolsSmtpCheck.validHostname(domain)
  }

  /**
   * bannerCheck
   */
   static bannerCheck(domain) {
    return domain
  }

  // private instance method
  _bannerCheck(domain) {
    return sendosToolsSmtpCheck.bannerCheck(domain)
  }

  /**
   * tls
   */
   static tls(domain) {
    return domain
  }

  // private instance method
  _tls(domain) {
    return sendosToolsSmtpCheck.tls(domain)
  }

  /**
   * openRelay
   */
   static openRelay(domain) {
    return domain
  }

  // private instance method
  _openRelay(domain) {
    return sendosToolsSmtpCheck.openRelay(domain)
  }

  /**
   * Wrap of dns.resolveMx native method.
   *
   * @static
   * @param {string} hostname - The hostname you want to resolve, i.e. gmail.com
   * @returns {Object[]} - Returns MX records array { priority, exchange }
   * @memberof sendosToolsSmtpCheck
   */
   static async resolveMx(domain) {
    // mx check
    try {
      let mxRecords = await resolveMx(domain)
      return mxRecords.sort((a, b) => a.priority - b.priority)
    } catch (err) {
      return []
    }
  }

  // private instance method
  _resolveMx(domain) {
    return sendosToolsSmtpCheck.resolveMx(domain)
  }

  /**
   * Runs the SMTP mailbox check. Commands for HELO/EHLO, MAIL FROM, RCPT TO.
   *
   * @static
   * @param {Object} config - Object of parameters for Smtp Mailbox resolution.
   * @param {string} config.domainOrEmail - The email address you want to check.
   * @param {object[]} config.mxRecords - The MX Records array supplied from resolveMx.
   * @param {number} config.timeout - Timeout parameter for the SMTP routine.
   * @param {string} config.mailFrom - The email address supplied to the MAIL FROM SMTP command.
   * @returns {object[]} - Object of SMTP responses [ {command, status, message} ]
   * @memberof sendosToolsSmtpCheck
   */
   static resolveSmtp({ mxRecords, timeout }) {
    return new Promise((resolve, reject) => {
      const host = mxRecords[0].exchange
      const fromHost = randomstring.generate(7).toLowerCase() + ".example.com"
      const mailFrom = "supertool@sendos.pro"
      const mailTo = "notrelay@" + fromHost

      let startTime = new Date().getTime()

      const commands = [
      `EHLO ${fromHost}`,
      `MAIL FROM: <${mailFrom}>`,
      `RCPT TO: <${mailTo}>`
      ]

      const stepMax = commands.length - 1
      let step = 0

      const smtp = net.createConnection({ port: 25, host })

      let smtpMessages = []

      smtp.setEncoding("ascii")
      smtp.setTimeout(timeout)

      smtp.on("error", err => {
        smtp.end(() => {
          reject(err)
        })
      })

      smtp.on("data", data => {
        const status = parseInt(data.substring(0, 3))
        const responce = data.split("\r\n").slice(0, -1)

        if (status === 220) {
          smtpMessages.push({
            command: "CONNECT",
            message: data,
            status,
            time: new Date().getTime() - startTime
          })
        } else {
          smtpMessages.push({
            command: commands[step - 1],
            message: responce.length == 1 ? data : responce,
            status,
            time: new Date().getTime() - startTime
          })
        }

        // if (status > 200) {
          if (step <= stepMax) {
            startTime = new Date().getTime()
            smtp.write(commands[step] + "\r\n")
            step++
          } else {
            smtp.write("QUIT\r\n")
            smtp.end(() => {
              resolve(smtpMessages)
            })
          }
        // }
      })
    })
  }

  // private instance method
  _resolveSmtp({ domain, mxRecords, timeout }) {
    return sendosToolsSmtpCheck.resolveSmtp({
      domain,
      mxRecords,
      timeout
    })
  }

  /**
   * Runs the email validation routine and supplies a final result.
   *
   * @returns {Object} - The instance state object containing all of the isValid* boolean checks, MX Records, and SMTP Messages.
   * @memberof sendosToolsSmtpCheck
   */
   async check() {
    console.log("resolvePattern")
    // resolvePattern
    const isValidSyntax = this._resolvePattern(this.state.domain)
    if (!isValidSyntax) {
      this.state.errors.push("Domain or email pattern is invalid.")
      return this.state
    }

    // resolveMx
    try {
      console.log("resolveMx")
      const mxRecords = await this._resolveMx(this.state.domain)
      const isValidMxRecord = mxRecords.length > 0
      this.state.mxRecords = mxRecords
      this.state.isValidMxRecord = isValidMxRecord
      if (!isValidMxRecord) {
        this.state.errors.push("MX record not found.")
        return this.state
      }
    } catch (err) {
      this.state.error.push("MX record not found.")
      return this.state
      throw new Error("MX record check failed.")
    }

    // resolveSmtp
    try {
      console.log("resolveSmtp")
      const { domain, mxRecords, timeout } = this.state
      const smtpMessages = await this._resolveSmtp({
        domain,
        mxRecords,
        timeout
      })
      this.state.smtpMessages = smtpMessages

    } catch (err) {
      this.state.errors.push("Email server is invalid or not available.")
      return this.state
      throw new Error('Mailbox check failed.')
    }

    // rDnsMismatch
    try {
      console.log("rDnsMismatch")
      const isRdnsMismatch = this._rDnsMismatch(this.state.domain)

      // this.state.rDnsMismatch = rDnsMismatch
    } catch (err) {
      throw new Error("rDnsMismatch check failed.")
    }

    // validHostname
    try {
      console.log("validHostname")
      const isValidHostname = this._validHostname(this.state.domain)

    } catch (err) {
      throw new Error("validHostname check failed.")
    }

    // bannerCheck
    try {
      console.log("bannerCheck")
      const isBannerCheck = this._bannerCheck(this.state.domain)

    } catch (err) {
      throw new Error("bannerCheck check failed.")
    }

    // tls
    try {
      console.log("tls")
      const isTls = this._tls(this.state.domain)

    } catch (err) {
      throw new Error("tls check failed.")
    }

    // openRelay
    try {
      console.log("openRelay")
      const isOpenRelay = this._openRelay(this.state.domain)

    } catch (err) {
      console.log(err)
      throw new Error("openRelay check failed.")
    }

    // FINISH
    const isComplete = this.state.smtpMessages.length === 4
    let result = ""

    if (isComplete) {
      const { status } = this.state.smtpMessages[3]
      // OK RESPONSE
      if (status === 250) {
        // result = 'Mailbox is valid.'
        this.state.result = true
      } else {
        // result = 'Mailbox is invalid.'
        this.state.result = false
      }
    } else {
      // result = 'Could not validate mailbox.'
      this.state.result = false
    }
    
    console.log("FINISH")
    
    return this.state

  }
}

module.exports = sendosToolsSmtpCheck