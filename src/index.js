/**
 * @title sendosToolsMailValidate  
 */

import dns from 'dns'
import net from 'net'
import os from 'os'

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

/**
 * Email address validation and SMTP verification API.

 * @param {Object} config - The email address you want to validate.
 * @param {string} config.emailAddress - The email address you want to validate.
 * @param {string} [config.mailFrom] - The email address used for the mail from during SMTP mailbox validation.
 * @param {string[]} [config.invalidMailboxKeywords] - Keywords you want to void, i.e. noemail, noreply etc.
 * @param {number} [config.timeout] - The timeout parameter for SMTP mailbox validation.
 * @returns {instance}
 * @class sendosToolsMailValidate
 */
class sendosToolsMailValidate {
  constructor({ emailAddress, invalidMailboxKeywords, timeout, mailFrom }) {
    this.state = {
      // args
      emailAddress,
      timeout: timeout || 3000,
      invalidMailboxKeywords: invalidMailboxKeywords || [],
      mailFrom: mailFrom || 'stalker@'+os.hostname() || 'stalker@example.org',
      // helpers
      mailbox: emailAddress.split('@')[0],
      realMail: emailAddress.split('@')[0],
      hostname: emailAddress.split('@')[1],
      mxRecords: [],
      smtpMessages: [],
      // results
      isValidSyntax: false,
      isValidMxRecord: false,
      isValidDeliver: false,
      isFreeMail: false,
      isDisposable: false,
      isSynonym: false,
      result: ''
    }
  }

  /**
   * Determines if the email address pattern is valid based on regex and invalid keyword check.
   * 
   * @static
   * @param {string} emailAddress - The full email address ypu want to check.
   * @returns {boolean} 
   * @memberof sendosToolsMailValidate
   */
  static resolvePattern(emailAddress, invalidMailboxKeywords = []) {
    const mailbox = emailAddress.split('@')[0]
    const regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    
    const isValidPattern = regex.test(emailAddress)
    
    return isValidPattern
  }

  // private instance method
  _resolvePattern(emailAddress, invalidMailboxKeywords = []) {
    return sendosToolsMailValidate.resolvePattern(emailAddress)
  }

  /**
   * Free mail check
   */
  static freeMail(emailAddress) {
    
    var freeList = ['aol.com','aol.de','aol.fr','aol.co.uk','aol.com','aol.com','aol.com','icloud.com','icloud.com','azet.sk','spamcombat.com','bol.com.br','eclipso.de','free.fr','free.fr','free.fr','freenet.de','gmail.com','gmx.com','gmx.de','desktopemail.com','buyemailsoftware.com','hotmail.com','laposte.net','libero.it','vendasrd.com.br','mail.com','mail.ru','netcourrier.com','expertarticles.com','outlook.com','outlook.com.br','outlook.de','outlook.fr','outlook.com','outlook.com','seznam.cz','sfr.fr','sfr.fr','sfr.fr','justlan.com','virgilio.it','web.de','yahoo.com.br','yahoo.ca','yahoo.com','yahoo.co.uk','yahoo.com','yandex.ru','zoho.com','userflowhq.com','list.ru','bk.ru','ukr.net','inbox.ru','yandex.by','ya.by','ya.ru','yandex.com','ya.com','rambler.ru','freemail.ru','km.ru','bossmail.ru','girlmail.ru','boymail.ru','safebox.ru','megabox.ru','tw24.ru','bigmir.net','i.ua','ua.fm','email.ua','football.ua','3g.ua','qip.ru','borda.ru','pochta.ru','fromru.com','front.ru','hotbox.ru','hotmail.ru','krovatka.su','land.ru','mail15.com','mail333.com','newmail.ru','nightmail.ru','nm.ru','pisem.net','pochtamt.ru','pop3.ru','rbcmail.ru','smtp.ru','5ballov.ru','aeterna.ru','ziza.ru','memori.ru','photofile.ru','fotoplenka.ru','pochta.com','webmail.ru','lenta.ru','autorambler.ru','myrambler.ru','ro.ru','rambler.ua'];

    const domain = emailAddress.split('@')[1].toLowerCase()
    
    return freeList.indexOf(domain) >= 0 ? true : false

  }

  // private instance method
  _freeMail(emailAddress) {
    return sendosToolsMailValidate.freeMail(emailAddress)
  }


  /**
   * Disposable Checked
   */
  static dispCheck(emailAddress) {
    
    var disposableList = ['oou.us', 'deyom.com', 'p33.org', '@rootfest.net', 'polyfaust.com', 'cartelera.org','hostcalls.com','fosil.pro','tempm.ml','usa.cc','igg.biz','email-temp.com','amail.club','cmail.club','wmail.club','duck2.club','cars2.club','banit.club','banit.me','nada.ltd','nada.email','getnada.com','tempmail.de','spybox.de','temp-mail.de','shitmail.de','sharklasers.com','guerrillamail.info','grr.la','guerrillamail.biz','guerrillamail.com','guerrillamail.de','guerrillamail.net','guerrillamail.org','guerrillamailblock.com','pokemail.net','spam4.me','tempr.email','discard.email','discardmail.com','discardmail.de','spambog.com','spambog.de','spambog.ru','0815.ru','hulapla.de','teewars.org','pfui.ru','0815.su','sweetxxx.de','zaktouni.fr','freelance-france.eu','webcontact-france.eu','fast-mail.fr','mail-easy.fr','instantmail.fr','btcmail.pw','knol-power.nl','hartbot.de','freundin.ru','cyber-phone.eu','premium-mail.fr','disign-concept.eu','ecolo-online.fr','photo-impact.eu','web-ideal.fr','wazabi.club','used-product.fr','cyber-innovation.club','reality-concept.club','last-chance.pro','disign-revelation.com','art-en-ligne.pro','solar-impact.pro','smashmail.de','jet-renovation.fr','estate-invest.fr','mail707.com','s0ny.net','affiliate-nebenjob.info','affilikingz.de','ausgefallen.info','camping-grill.info','digitalesbusiness.info','klick-tipp.us','mainerfolg.info','xn--d-bga.net','333.igg.biz','ab0.igg.biz','j8k2.usa.cc','blow-job.nut.cc','cc-cc.usa.cc','usa-cc.usa.cc','nut-cc.nut.cc','flu-cc.flu.cc','sohai.ml','flucc.flu.cc','nutcc.nut.cc','jamesbond.usa.cc','jamesbond.nut.cc','jamesbond.flu.cc','jamesbond.igg.biz','securemail.igg.biz','securemail.flu.cc','securemail.nut.cc','securemail.usa.cc','pw.securemail.usa.cc','ks87.igg.biz','ks87.usa.cc','monachat.tk','mailinator.usa.cc','yopmail.usa.cc','kiryubox.cu.cc','mp.igg.biz','0-00.usa.cc','rs6.igg.biz','pw.rs6.igg.biz','pw.shitt.igg.biz','web-mail.igg.biz','pw.mymail.igg.biz','s.mymail.igg.biz','area51.usa.cc','area51.igg.biz','area51.flu.cc','area51.nut.cc','password.flu.cc','pw.rs6.usa.cc','&nbsp;</option>top9appz.info','nawmin.info','joseihorumon.info','lacto.info','kappala.info','macromice.info','lifetimefriends.info','daibond.info','trgovinanaveliko.info','easynetwork.info','thedirhq.info','imul.info','totoan.info','adubiz.info','300book.info','2wc.info','upozowac.info','bbbbyyzz.info','mebelnu.info','goround.info','masonline.info','giveh2o.info','freedom4you.info','u14269.ml','buchhandlung24.com','newideasfornewpeople.info','yopmail.fr','yopmail.net','cool.fr.nf','jetable.fr.nf','nospam.ze.tc','nomail.xl.cx','mega.zik.dj','speed.1s.fr','courriel.fr.nf','moncourrier.fr.nf','monemail.fr.nf','monmail.fr.nf']; 

    const domain = emailAddress.split('@')[1].toLowerCase()
      
    return disposableList.indexOf(domain) >= 0 ? true : false

  }

  // private instance method
  _dispCheck(emailAddress) {
    return sendosToolsMailValidate.dispCheck(emailAddress)
  }


  /**
   * Synonym check
   */
  static synonymCheck(emailAddress) {
    
    const addres = emailAddress.split('@')[0].toLowerCase()
    const synonym = addres.split('+')[1]
    const real = addres.split('+')[0]
    
    if(synonym) {
      return {
        result: true,
        realUser: real
      }
    }

    return {
      result: false,
      realUser: addres
    }

  }

  // private instance method
  _synonymCheck(emailAddress) {
    return sendosToolsMailValidate.synonymCheck(emailAddress)
  }

  /**
   * Wrap of dns.resolveMx native method.
   * 
   * @static
   * @param {string} hostname - The hostname you want to resolve, i.e. gmail.com
   * @returns {Object[]} - Returns MX records array { priority, exchange }
   * @memberof sendosToolsMailValidate
   */
  static async resolveMx(hostname) {
    // mx check
    try {
      let mxRecords = await resolveMx(hostname)
      return mxRecords.sort((a, b) => a.priority - b.priority)
    } catch (err) {
      return []
    }
  }

  // private instance method
  _resolveMx(hostname) {
    return sendosToolsMailValidate.resolveMx(hostname)
  }

  /**
   * Runs the SMTP mailbox check. Commands for HELO/EHLO, MAIL FROM, RCPT TO.
   * 
   * @static
   * @param {Object} config - Object of parameters for Smtp Mailbox resolution.
   * @param {string} config.emailAddress - The email address you want to check.
   * @param {object[]} config.mxRecords - The MX Records array supplied from resolveMx.
   * @param {number} config.timeout - Timeout parameter for the SMTP routine.
   * @param {string} config.mailFrom - The email address supplied to the MAIL FROM SMTP command.
   * @returns {object[]} - Object of SMTP responses [ {command, status, message} ]
   * @memberof sendosToolsMailValidate
   */
  static resolveSmtpMailbox({ emailAddress, mxRecords, timeout, mailFrom }) {
    return new Promise((resolve, reject) => {

      const host = mxRecords[0].exchange
      const domain = emailAddress.split('@')[1]

      const commands = [
        `HELO ${host}`,
        `MAIL FROM: <${mailFrom}>`,
        `RCPT TO: <${emailAddress}>`
      ]

      const stepMax = commands.length - 1
      let step = 0

      const smtp = net.createConnection({ port: 25, host }, () => {
        // console.log('Connected to ' + host);
      })

      let smtpMessages = []

      smtp.setEncoding('ascii')
      smtp.setTimeout(timeout)

      smtp.on('error', err => {
        smtp.end(() => {
          reject(err)
        })
      })

      smtp.on('data', data => {

        const status = parseInt(data.substring(0, 3))

        if(status !== 220) {
          smtpMessages.push({
            command: commands[step - 1],
            message: data,
            status
          })
        }

        if (status > 200) {
          if (step <= stepMax) {
            smtp.write(commands[step] + '\r\n')
            step++
          } else {
            smtp.write('QUIT\r\n');
            smtp.end(() => {
              resolve(smtpMessages)
            })
          }
        }

      })


    })
  }
  // private instance method
  _resolveSmtpMailbox({ emailAddress, mxRecords, timeout, mailFrom }) {
    return sendosToolsMailValidate.resolveSmtpMailbox({
      emailAddress,
      mxRecords,
      timeout,
      mailFrom
    })
  }




checkViaSmtp(address) {
    const domain = EmailValidator.extractDomain(address);
    return EmailValidator.resolveMxRecords(address)
      .then(mxRecords => {
        return new Promise((resolve, reject) => {
          const socket = net.connect(25, mxRecords[0]);
          const errorHandler = message => {
            socket.write('QUIT\r\n');
            socket.end();
            reject(new Error('Got an error from the server: ' + message));
          };
          const messages = [
            `EHLO ${domain}`,
            `MAIL FROM: <${address}>`,
            `RCPT TO: <${address}>`
          ];
          socket.on('data', data => {
            data = data.toString();
            if (!data.includes(220) && !data.includes(250)) return errorHandler(data);
            if (messages.length > 0) {
              return socket.write(messages.shift() + '\r\n');
            }
            socket.write('QUIT\r\n');
            socket.end();
            resolve(mxRecords);
          });
          socket.on('error', err => {
            if (mxRecords) {
              err.mxRecords = mxRecords;
            }
            reject(err)
          });
          setTimeout(() => reject(new Error('Connection timed out')), this.options.timeout);
        });
      });
  }




  /**
   * Runs the email validation routine and supplies a final result.
   * 
   * @returns {Object} - The instance state object containing all of the isValid* boolean checks, MX Records, and SMTP Messages.
   * @memberof sendosToolsMailValidate
   */
  async check() {
   

    // Pattern check
    const isValidSyntax = this._resolvePattern(
      this.state.emailAddress,
      this.state.invalidMailboxKeywords
    )
    this.state.isValidSyntax = isValidSyntax

    if (!isValidSyntax) {
      this.state.result = 'Email pattern is invalid.'
      return this.state
    }

    // FreeMail check
    try {
      
      // isFreeMail check
      const isFreeMail = this._freeMail(
        this.state.emailAddress
      )

      this.state.isFreeMail = isFreeMail

    } catch (err) {
      throw new Error('Free mail check failed.')
    }

    // Disposable check
    try {

      // Disposable check
      const isDisposable = this._dispCheck(
        this.state.emailAddress
      )

      this.state.isDisposable = isDisposable
     
     
    } catch (err) {
      throw new Error('Disposable check failed.')
    }

    // Synonim check
    try {
      
      // Synonim check
      const isSynonym = this._synonymCheck(
        this.state.emailAddress
      )

      this.state.isSynonym = isSynonym.result
      this.state.realMail = isSynonym.realUser

    } catch (err) {
      throw new Error('Synonim check failed.')
    } 

    // MX check
    try {
      const mxRecords = await this._resolveMx(this.state.hostname)
      const isValidMxRecord = mxRecords.length > 0
      this.state.mxRecords = mxRecords
      this.state.isValidMxRecord = isValidMxRecord

      if (!isValidMxRecord) {
        this.state.result = 'Email server is invalid or not available.'
        return this.state
      }
    } catch (err) {
      throw new Error('MX record check failed.')
    }

    // Mailbox check
    try {
      const { emailAddress, mxRecords, timeout, mailFrom } = this.state
      const smtpMessages = await this._resolveSmtpMailbox({
        emailAddress,
        mxRecords,
        timeout,
        mailFrom
      })
      this.state.smtpMessages = smtpMessages
      const isComplete = smtpMessages.length === 3
      let result = ''

      if (isComplete) {
        const { status } = smtpMessages[2]
        // OK RESPONSE
        if (status === 250) {
          // result = 'Mailbox is valid.'
          result = true
          this.state.result = result
          this.state.isValidDeliver = true
        } else {
          // result = 'Mailbox is invalid.'
          result = false
          this.state.result = result
          this.state.isValidDeliver = false
        }
      } else {
        // result = 'Could not validate mailbox.'
        result = false
        this.state.result = result
        this.state.isValidDeliver = false
      }
      return this.state
    } catch (err) {
      // throw new Error('Mailbox check failed.')
      result = true
      this.state.result = result
      this.state.isValidDeliver = true
    }
  }
}

module.exports = sendosToolsMailValidate
