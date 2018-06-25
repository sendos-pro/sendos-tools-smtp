"use strict";

var _dns = require("dns");

var _dns2 = _interopRequireDefault(_dns);

var _net = require("net");

var _net2 = _interopRequireDefault(_net);

var _os = require("os");

var _os2 = _interopRequireDefault(_os);

var _randomstring = require("randomstring");

var _randomstring2 = _interopRequireDefault(_randomstring);

var _maxmind = require("maxmind");

var _maxmind2 = _interopRequireDefault(_maxmind);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; } /**
                                                                                                                                                                                                                                                                                                                                                                                                                                                                            * @title sendosToolsSmtpCheck
                                                                                                                                                                                                                                                                                                                                                                                                                                                                            */

const resolveMx = hostname => {
  return new Promise((resolve, reject) => {
    _dns2.default.resolveMx(hostname, (err, val) => {
      if (err) {
        return reject(err);
      }
      val.forEach(function (item, i, arr) {
        let domain = val[i].exchange;

        _dns2.default.resolve4(domain, (err, ipv4) => {
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
  static resolveMx(domain) {
    return _asyncToGenerator(function* () {
      // mx check
      try {
        let mxRecords = yield resolveMx(domain);
        return mxRecords.sort(function (a, b) {
          return a.priority - b.priority;
        });
      } catch (err) {
        return [];
      }
    })();
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
      const fromHost = _randomstring2.default.generate(7).toLowerCase() + ".example.com";
      const mailFrom = "supertool@sendos.pro";
      const mailTo = "notrelay@" + fromHost;
      let transactionTime = 0;

      let startTime = new Date().getTime();

      const commands = [{ command: `EHLO ${fromHost}`, type: "ehlo" }, { command: `MAIL FROM: <${mailFrom}>`, type: "mailFrom" }, { command: `RCPT TO: <${mailTo}>`, type: "rcptTo" }];

      const stepMax = commands.length - 1;
      let step = 0;

      const smtp = _net2.default.createConnection({ port: 25, host });

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
  check() {
    var _this = this;

    return _asyncToGenerator(function* () {
      // resolvePattern
      const isValidSyntax = _this._resolvePattern(_this.state.domain);
      if (!isValidSyntax) {
        _this.state.errors.push("Domain or email pattern is invalid.");
        return _this.state;
      }

      // resolveMx
      try {
        const mxRecords = yield _this._resolveMx(_this.state.domain);
        const isValidMxRecord = mxRecords.length > 0;
        _this.state.mxRecords = mxRecords;
        if (!isValidMxRecord) {
          _this.state.errors.push("MX record not found.");
          return _this.state;
        }
      } catch (err) {
        _this.state.error.push("MX record not found.");
        return _this.state;
        throw new Error("resolveMx check failed.");
      }

      // resolveSmtp
      try {
        const { domain, mxRecords, options } = _this.state;
        let timeout = options.timeout;
        const smtpMessages = yield _this._resolveSmtp({
          domain,
          mxRecords,
          timeout
        });
        _this.state.smtpMessages = smtpMessages.response;
        _this.state.transactionTime = smtpMessages.transactionTime * 5;
      } catch (err) {
        _this.state.errors.push("Email server is invalid or not available.");
        return _this.state;
        throw new Error("resolveSmtp check failed.");
      }

      // rDnsMismatch
      try {
        const isRdnsMismatch = _this._rDnsMismatch(_this.state.domain);

        // this.state.rDnsMismatch = rDnsMismatch
      } catch (err) {
        throw new Error("rDnsMismatch check failed.");
      }

      // validHostname
      try {
        const isValidHostname = _this._validHostname(_this.state.domain);
      } catch (err) {
        throw new Error("validHostname check failed.");
      }

      // bannerCheck
      try {
        const isBannerCheck = _this._bannerCheck(_this.state.domain);
      } catch (err) {
        throw new Error("bannerCheck check failed.");
      }

      // tls
      try {
        const isTls = _this._tls(_this.state.domain);
      } catch (err) {
        throw new Error("tls check failed.");
      }

      // openRelay
      try {
        const isOpenRelay = _this._openRelay(_this.state.domain);
      } catch (err) {
        console.log(err);
        throw new Error("openRelay check failed.");
      }

      // FINISH
      const isComplete = _this.state.smtpMessages.length === 4;
      let result = "";

      if (isComplete) {
        const { status } = _this.state.smtpMessages[0];
        // OK RESPONSE
        if (status === 220) {
          _this.state.result = true;
        } else {
          _this.state.result = false;
        }
      } else {
        _this.state.result = false;
      }
      return _this.state;
    })();
  }
}

module.exports = sendosToolsSmtpCheck;