/**
 * @title sendosToolsSmtpCheck
 */

import dns from "dns";
import net from "net";
import os from "os";
import randomstring from "randomstring";
import maxmind from "maxmind";

const resolveMx = hostname => {
  return new Promise((resolve, reject) => {
    dns.resolveMx(hostname, (err, val) => {
      if (err) {
        return reject(err);
      }
      val.forEach(function(item, i, arr) {
        let domain = val[i].exchange;

        dns.resolve4(domain, (err, ipv4) => {
          if (!err) {
            val[i].ip = ipv4[0];
          }
        });
      });
      resolve(val);
    });
  });
};

const isMail = domainOrEmail => {
  const regex = /^(([^<>()\[\]\\.,:\s@"]+(\.[^<>()\[\]\\.,:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  const isValidPattern = regex.test(domainOrEmail);
  return isValidPattern;
};

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
    let domain = domainOrEmail.toLowerCase();

    if (isMail(domain)) {
      domain = domain.split("@")[1];
    }

    this.state = {
      // result
      result: false,
      // args
      domain,
      transactionTime: 0,
      // results
      rDnsMismatch: {
        result: false,
        info: false
      },
      validHostname: {
        result: false,
        info: false
      },
      bannerCheck: {
        result: false,
        info: false
      },
      supportTls: {
        result: false,
        info: false
      },
      openRelay: {
        result: false,
        info: false
      },
      catchAll: {
        result: false,
        info: false
      },
      // helpers
      mxRecords: [],
      smtpMessages: [],
      errors: [],
      options: {
        timeout: timeout || 10000
      }
    };
  }

  /**
   * Check pattern
   */
  static resolvePattern(domain) {
    const regex = /^[a-zA-Z0-9_-]+\.[.a-zA-Z0-9_-]+$/;
    return regex.test(domain);
  }

  // private instance method
  _resolvePattern(domain) {
    return sendosToolsSmtpCheck.resolvePattern(domain);
  }

  /**
   * rDnsMismatch
   */
  static rDnsMismatch(domain) {
    return domain;
  }

  // private instance method
  _rDnsMismatch(domain) {
    return sendosToolsSmtpCheck.rDnsMismatch(domain);
  }

  /**
   * validHostname
   */
  static validHostname(domain) {
    return domain;
  }

  // private instance method
  _validHostname(domain) {
    return sendosToolsSmtpCheck.validHostname(domain);
  }

  /**
   * bannerCheck
   */
  static bannerCheck(domain) {
    return domain;
  }

  // private instance method
  _bannerCheck(domain) {
    return sendosToolsSmtpCheck.bannerCheck(domain);
  }

  /**
   * tls
   */
  static tls(domain) {
    return domain;
  }

  // private instance method
  _tls(domain) {
    return sendosToolsSmtpCheck.tls(domain);
  }

  /**
   * openRelay
   */
  static openRelay(domain) {
    return domain;
  }

  // private instance method
  _openRelay(domain) {
    return sendosToolsSmtpCheck.openRelay(domain);
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
      let mxRecords = await resolveMx(domain);
      return mxRecords.sort((a, b) => a.priority - b.priority);
    } catch (err) {
      return [];
    }
  }

  // private instance method
  _resolveMx(domain) {
    return sendosToolsSmtpCheck.resolveMx(domain);
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
      const host = mxRecords[0].exchange;
      const fromHost = randomstring.generate(7).toLowerCase() + ".example.com";
      const mailFrom = "supertool@sendos.pro";
      const mailTo = "notrelay@" + fromHost;
      let transactionTime = 0;

      let startTime = new Date().getTime();

      const commands = [
        { command: `EHLO ${fromHost}`, type: "ehlo" },
        { command: `MAIL FROM: <${mailFrom}>`, type: "mailFrom" },
        { command: `RCPT TO: <${mailTo}>`, type: "rcptTo" }
      ];

      const stepMax = commands.length - 1;
      let step = 0;

      const smtp = net.createConnection({ port: 25, host });

      let smtpMessages = [];

      smtp.setEncoding("ascii");
      smtp.setTimeout(timeout);

      smtp.on("error", err => {
        smtp.end(() => {
          reject(err);
        });
      });

      smtp.on("data", data => {
        const status = parseInt(data.substring(0, 3));
        const response = data.split("\r\n").slice(0, -1);

        let queryTime = new Date().getTime() - startTime;

        transactionTime += queryTime;

        if (status === 220) {
          smtpMessages.push({
            command: "connection",
            responce: data,
            status,
            time: queryTime
          });
        } else {
          let type = commands[step - 1].type;
          smtpMessages.push({
            command: type,
            responce: response.length == 1 ? data : response,
            status,
            time: queryTime
          });
        }

        // if (status > 200) {
        if (step <= stepMax) {
          startTime = new Date().getTime();
          smtp.write(commands[step].command + "\r\n");
          step++;
        } else {
          smtp.write("QUIT\r\n");
          smtp.end(() => {
            resolve({
              transactionTime: transactionTime,
              response: smtpMessages
            });
          });
        }
        // }
      });
    });
  }

  // private instance method
  _resolveSmtp({ domain, mxRecords, timeout }) {
    return sendosToolsSmtpCheck.resolveSmtp({
      domain,
      mxRecords,
      timeout
    });
  }

  /**
   * Runs the email validation routine and supplies a final result.
   *
   * @returns {Object} - The instance state object containing all of the isValid* boolean checks, MX Records, and SMTP Messages.
   * @memberof sendosToolsSmtpCheck
   */
  async check() {
    // resolvePattern
    const isValidSyntax = this._resolvePattern(this.state.domain);
    if (!isValidSyntax) {
      this.state.errors.push("Domain or email pattern is invalid.");
      return this.state;
    }

    // resolveMx
    try {
      const mxRecords = await this._resolveMx(this.state.domain);
      const isValidMxRecord = mxRecords.length > 0;
      this.state.mxRecords = mxRecords;
      if (!isValidMxRecord) {
        this.state.errors.push("MX record not found.");
        return this.state;
      }
    } catch (err) {
      this.state.error.push("MX record not found.");
      return this.state;
      throw new Error("resolveMx check failed.");
    }

    // resolveSmtp
    try {
      const { domain, mxRecords, options } = this.state;
      let timeout = options.timeout;
      const smtpMessages = await this._resolveSmtp({
        domain,
        mxRecords,
        timeout
      });
      this.state.smtpMessages = smtpMessages.response;
      this.state.transactionTime = smtpMessages.transactionTime * 5;
    } catch (err) {
      this.state.errors.push("Email server is invalid or not available.");
      return this.state;
      throw new Error("resolveSmtp check failed.");
    }

    // rDnsMismatch
    try {
      const isRdnsMismatch = this._rDnsMismatch(this.state.domain);

      // this.state.rDnsMismatch = rDnsMismatch
    } catch (err) {
      throw new Error("rDnsMismatch check failed.");
    }

    // validHostname
    try {
      const isValidHostname = this._validHostname(this.state.domain);
    } catch (err) {
      throw new Error("validHostname check failed.");
    }

    // bannerCheck
    try {
      const isBannerCheck = this._bannerCheck(this.state.domain);
    } catch (err) {
      throw new Error("bannerCheck check failed.");
    }

    // tls
    try {
      const isTls = this._tls(this.state.domain);
    } catch (err) {
      throw new Error("tls check failed.");
    }

    // openRelay
    try {
      const isOpenRelay = this._openRelay(this.state.domain);
    } catch (err) {
      console.log(err);
      throw new Error("openRelay check failed.");
    }

    // FINISH
    const isComplete = this.state.smtpMessages.length === 4;
    let result = "";

    if (isComplete) {
      const { status } = this.state.smtpMessages[0];
      // OK RESPONSE
      if (status === 220) {
        this.state.result = true;
      } else {
        this.state.result = false;
      }
    } else {
      this.state.result = false;
    }
    return this.state;
  }
}

module.exports = sendosToolsSmtpCheck;