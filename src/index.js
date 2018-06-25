/**
 * @title sendosToolsSmtpCheck
 */

import dns from "dns";
import net from "net";
import os from "os";
import randomstring from "randomstring";

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
  constructor({ value, timeout }) {
    // Почтовый адрес. Домен. Айпи. MX

    // Проверим МКС у домена, если есть, то работаем как с МКС, если нет, то проверяем на соединение
    value = value.toLowerCase();

    this.state = {
      // result
      result: false,
      // args
      value,
      // domain,
      aRecord: "",
      ptrRecord: "",
      smtpBanner: "",
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
      // mxRecords: [],
      smtpMessages: [],
      errors: [],
      options: {
        timeout: timeout || 15000
      }
    };
  }

  /**
   * Check pattern
   */
  static resolvePattern(value) {
    return new Promise((resolve, reject) => {
      const domainRegex = /^[a-zA-Z0-9_-]+\.[.a-zA-Z0-9_-]+$/;
      const ipRegex = /(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?:\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}/;

      let result = {};

      if (ipRegex.test(value)) {
        // if IP
        dns.resolvePtr(value, (err, ptr) => {
          if (err) return reject("Cant get PTR record");
          result.aRecord = value;
          result.ptrRecord = ptr;
          resolve(result);
        });
      } else if (domainRegex.test(value)) {
        dns.resolve4(value, (err, arecord) => {
          // if DOMAIN
          // if(err) console.log(ptr)
          if (err) return reject("Cant get A record");

          let ipv4 = arecord[0];

          dns.reverse(ipv4, (err, ptr) => {

            if (err) return reject("Cant get PTR record");
            result.aRecord = ipv4;
            result.ptrRecord = ptr[0];
            resolve(result);
          });
        });
      } else {
        return reject("MX or IP-address pattern is invalid.");
      }
    });
  }

  // private instance method
  _resolvePattern(value) {
    return sendosToolsSmtpCheck.resolvePattern(value);
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
  static resolveSmtp({ host, timeout }) {
    return new Promise((resolve, reject) => {
      const fromHost = randomstring.generate(7).toLowerCase() + ".sendos.pro";
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
      const smtp = net.createConnection({ port: 25, host }, () => {
        // console.log("Connected to server!");
      });

      let smtpMessages = [];

      smtp.setEncoding("ascii");
      smtp.setTimeout(timeout);

      smtp.on("timeout", () => {
        smtp.destroy({code: 'ETIMEDOUT'});
      });

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
            command: "CONNECT",
            response: data,
            status,
            time: queryTime
          });
        } else {
          // let type = commands[step - 1].type;
          smtpMessages.push({
            command: commands[step - 1].command,
            response: response.length == 1 ? data : response,
            status,
            time: queryTime
          });
        }

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

      });
    });
  }

  // private instance method
  _resolveSmtp({ host, timeout }) {
    return sendosToolsSmtpCheck.resolveSmtp({
      host,
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
    try {
      const resolvePattern = await this._resolvePattern(this.state.value);

      let aRecord = resolvePattern.aRecord;
      let ptrRecord = resolvePattern.ptrRecord;

      this.state.aRecord = aRecord;
      this.state.ptrRecord = ptrRecord;
    } catch (err) {
      this.state.errors.push(err);
      return this.state;
      // throw new Error("resolvePattern check failed.");
    }

    // resolveSmtp
    try {
      const { value, options } = this.state;
      let timeout = options.timeout;
      let host = value;

      const smtpMessages = await this._resolveSmtp({
        host,
        timeout
      });

      this.state.smtpMessages = smtpMessages.response;
      this.state.transactionTime = smtpMessages.transactionTime * 5;
      // this.state.result = true;
       
    } catch (err) {

      let timeout = this.state.options.timeout;
      let message = 'Unable to connect ' + this.state.value

      if(err.code == 'ETIMEDOUT') {
        message = "Unable to connect "+ this.state.value +" after " + timeout / 1000 + " seconds."
      }

      this.state.errors.push(message);
      return this.state;
      // throw new Error("resolveSmtp check failed.");
    }


    // bannerCheck
    try {
      const isBannerCheck = this._bannerCheck(this.state.domain);

      // this.state.smtpBanner = smtpMessages.smtpBanner;
    } catch (err) {
      throw new Error("bannerCheck check failed.");
    }

    // rDnsMismatch
    try {
      const isRdnsMismatch = this._rDnsMismatch(this.state.domain);

      this.state.rDnsMismatch = isRdnsMismatch;
    } catch (err) {
      throw new Error("rDnsMismatch check failed.");
    }

    // validHostname
    try {
      const isValidHostname = this._validHostname(this.state.domain);
    } catch (err) {
      throw new Error("validHostname check failed.");
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

    if (isComplete) {
      const { status } = this.state.errors;

      if (this.state.errors.length === 0) {
        // this.state.result = true;
      }

    }

    return this.state;
  }
}

module.exports = sendosToolsSmtpCheck;