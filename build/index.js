"use strict";

var _dns = require("dns");

var _dns2 = _interopRequireDefault(_dns);

var _net = require("net");

var _net2 = _interopRequireDefault(_net);

var _os = require("os");

var _os2 = _interopRequireDefault(_os);

var _randomstring = require("randomstring");

var _randomstring2 = _interopRequireDefault(_randomstring);

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

const isIpv4 = value => {
  const regex = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
  return regex.test(value);
};

const isDomain = value => {
  const regex = /^(?=.{0,253}$)(([a-z0-9][a-z0-9-]{0,61}[a-z0-9]|[a-z0-9])\.)+((?=.*[^0-9])([a-z0-9][a-z0-9-]{0,61}[a-z0-9]|[a-z0-9]))$/i;
  return regex.test(value);
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
      hostName: '',
      smtpBanner: '',
      connectionTime: 0,
      transactionTime: 0,
      aRecords: [],
      // checked
      checks: {
        syntaxValid: {
          result: false
        },
        resolveRecord: {
          result: false
        },
        isConnected: {
          result: false
        },
        bannerCheck: {
          result: false
        },
        validHostname: {
          result: false
        },
        rDnsMismatch: {
          result: false
        },
        supportTls: {
          result: false
        },
        openRelay: {
          result: false
        }
      },
      // helpers
      smtpMessages: [],
      options: {
        timeout: timeout || 15000
      }
    };
  }

  /**
   * Check resolve record
   */
  static resolveRecord(value) {
    return new Promise((resolve, reject) => {
      let result = [];
      if (isIpv4(value)) {
        // if IP
        _dns2.default.reverse(value, (err, ptr) => {
          if (err) return reject("Can't get the PTR record");

          _dns2.default.resolve4(ptr[0], (err, aRecord) => {
            // console.log(aRecord)
            if (err) return reject("Can't get the A record");

            aRecord.forEach(function (item, i, arr) {
              _dns2.default.reverse(item, (err, ptr) => {
                if (err) return reject("Can't get the PTR record");
                result.push({ value: item, rDns: ptr[0] });

                if (arr.length - 1 == i) {
                  resolve(result);
                }
              });
            });
          });
        });
      } else if (isDomain(value)) {
        _dns2.default.resolve4(value, (err, aRecord) => {
          // if DOMAIN
          // if(err) console.log(ptr)
          if (err) return reject("Can't get the A record");

          aRecord.forEach(function (item, i, arr) {
            _dns2.default.reverse(item, (err, ptr) => {
              if (err) return reject("Can't get the PTR record");
              result.push({ value: item, rDns: ptr[0] });

              if (arr.length - 1 == i) {
                resolve(result);
              }
            });
          });
        });
      }
    });
  }

  // private instance method
  _resolveRecord(value) {
    return sendosToolsSmtpCheck.resolveRecord(value);
  }

  /**
   * Check pattern
   */
  static resolvePattern(value) {
    return new Promise((resolve, reject) => {
      if (isIpv4(value)) {
        resolve(true);
      } else if (isDomain(value)) {
        resolve(true);
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
  static rDnsMismatch(aRecord, value) {
    return new Promise((resolve, reject) => {
      if (isIpv4(value)) {
        aRecord.forEach(function (item, i, arr) {
          if (item.value == value) {
            resolve(true);
          }
        });
      } else if (isDomain(value)) {
        aRecord.forEach(function (item, i, arr) {
          if (item.rDns == value) {
            resolve(true);
          }
        });
      }

      resolve(false);
    });
  }

  // private instance method
  _rDnsMismatch(aRecord, value) {
    return sendosToolsSmtpCheck.rDnsMismatch(aRecord, value);
  }

  /**
   * validHostname
   */
  static validHostname(aRecord, hostName) {
    return new Promise((resolve, reject) => {
      aRecord.forEach(function (item, i, arr) {
        if (item.rDns === hostName) {
          resolve(true);
        }
      });
      resolve(false);
    });
  }

  // private instance method
  _validHostname(aRecord, hostName) {
    return sendosToolsSmtpCheck.validHostname(aRecord, hostName);
  }

  /**
   * bannerCheck
   */
  static bannerCheck(smtpBanner, aRecord) {
    return new Promise((resolve, reject) => {
      aRecord.forEach(function (item, i, arr) {
        if (item.rDns === smtpBanner) {
          resolve(true);
        }
      });
      resolve(false);
    });
  }

  // private instance method
  _bannerCheck(smtpBanner, aRecord) {
    return sendosToolsSmtpCheck.bannerCheck(smtpBanner, aRecord);
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
  static resolveSmtp({ host, timeout }) {
    return new Promise((resolve, reject) => {
      const fromHost = _randomstring2.default.generate(7).toLowerCase() + ".sendos.pro";
      const mailFrom = "supertool@sendos.pro";
      const mailTo = "notrelay@" + fromHost;
      let transactionTime = 0;
      let connectionTime = 0;
      let smtpBanner = false;

      let startTime = new Date().getTime();

      const commands = [{ command: `EHLO ${fromHost}`, type: "ehlo" }, { command: `MAIL FROM: <${mailFrom}>`, type: "mailFrom" }, { command: `RCPT TO: <${mailTo}>`, type: "rcptTo" }];

      const stepMax = commands.length - 1;
      let step = 0;
      const smtp = _net2.default.createConnection({ port: 25, host }, () => {
        // console.log("Connected to server!");
      });

      let smtpMessages = [];

      smtp.setEncoding("ascii");
      smtp.setTimeout(timeout);

      smtp.on("timeout", () => {
        smtp.destroy({ code: "ETIMEDOUT" });
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
          smtpBanner = data.match(/^220 (.+?) /)[1];
          connectionTime = queryTime;

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
              smtpBanner: smtpBanner,
              connectionTime: connectionTime,
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
  check() {
    var _this = this;

    return _asyncToGenerator(function* () {
      // resolvePattern
      try {
        const resolvePattern = yield _this._resolvePattern(_this.state.value);

        if (resolvePattern) {
          _this.state.checks.syntaxValid.result = true;
        } else {
          _this.state.checks.syntaxValid.error = "MX or IP-address pattern is invalid.";
        }
      } catch (err) {
        _this.state.checks.syntaxValid.error = "MX or IP-address pattern is invalid.";
        return _this.state;
        // throw new Error("resolvePattern check failed.");
      }

      // resolveRecord
      try {
        const resolveRecord = yield _this._resolveRecord(_this.state.value);

        _this.state.aRecords = resolveRecord;
        _this.state.checks.resolveRecord.result = true;
      } catch (err) {
        _this.state.checks.resolveRecord.error = err;
        return _this.state;
        // throw new Error("resolvePattern check failed.");
      }

      // resolveSmtp
      try {
        const { value, options } = _this.state;
        let timeout = options.timeout;
        let host = value;

        const smtpMessages = yield _this._resolveSmtp({
          host,
          timeout
        });

        _this.state.smtpMessages = smtpMessages.response;
        _this.state.smtpBanner = smtpMessages.smtpBanner;
        _this.state.transactionTime = smtpMessages.transactionTime * 5;
        _this.state.connectionTime = smtpMessages.connectionTime;
        _this.state.checks.isConnected.result = true;
      } catch (err) {
        let timeout = _this.state.options.timeout;
        let message = "Unable to connect " + _this.state.value;

        if (err.code == "ETIMEDOUT") {
          message = "Unable to connect " + _this.state.value + " after " + timeout / 1000 + " seconds.";
        }

        _this.state.checks.isConnected.error = message;
        return _this.state;
        // throw new Error("resolveSmtp check failed.");
      }

      // bannerCheck
      try {
        const isBannerCheck = yield _this._bannerCheck(_this.state.smtpBanner, _this.state.aRecords);

        if (isBannerCheck) {
          _this.state.checks.bannerCheck.result = true;
        } else {
          _this.state.checks.bannerCheck.error = "Smtp banner [" + _this.state.smtpBanner + "] does not match rDNS IP address";
        }
      } catch (err) {
        throw new Error("bannerCheck check failed.");
      }

      // rDnsMismatch
      try {
        const isRdnsMismatch = yield _this._rDnsMismatch(_this.state.aRecords, _this.state.value);

        if (isRdnsMismatch) {
          _this.state.checks.rDnsMismatch.result = true;
        } else {
          _this.state.checks.rDnsMismatch.error = _this.state.value + " not resolves to SMTP";
        }
      } catch (err) {
        throw new Error("rDnsMismatch check failed.");
      }

      // validHostname
      try {

        const hostName = _this.state.smtpMessages[1].response[0].match(/^250-(.+?)($| )/)[1];

        _this.state.hostName = hostName;

        const isValidHostname = yield _this._validHostname(_this.state.aRecords, hostName);

        if (isValidHostname) {
          _this.state.checks.validHostname.result = true;
        } else {
          _this.state.checks.validHostname.error = "rDNS is not a valid hostname!";
        }
      } catch (err) {
        throw new Error("validHostname check failed.");
      }

      // tls
      try {
        let response = _this.state.smtpMessages[1].response;

        if (response instanceof Array) {
          response = response.join();
        }

        const isTls = response.match(/250\-STARTTLS/);

        if (isTls) {
          _this.state.checks.supportTls.result = true;
        } else {
          _this.state.checks.supportTls.error = "No TLS / SSL support";
        }
      } catch (err) {
        throw new Error("tls check failed.");
      }

      // openRelay
      try {
        let response = _this.state.smtpMessages[3].response;

        if (response instanceof Array) {
          response = response.join();
        }

        const isOpenRelay = response.match(/^250/);
        if (!isOpenRelay) {
          _this.state.checks.openRelay.result = true;
        } else {
          _this.state.checks.openRelay.error = "Your server openRelay is bad!";
        }
      } catch (err) {
        throw new Error("openRelay check failed.");
      }

      // FINISH
      return _this.state;
    })();
  }
}

module.exports = sendosToolsSmtpCheck;