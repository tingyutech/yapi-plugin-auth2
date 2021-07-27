const axios = require('axios');
const get = require('lodash.get')
const controller = require('./controller');
const crypto = require('crypto');

function gets(obj, keys) {
  let value = ''

  if (Array.isArray(keys)) {
    keys.some((key) => {
      const v = get(obj, key)
      if (v) {
        value = v;
        return true
      }

      return false
    })
  } else {
    value = get(obj, keys)
  }

  return value
}

module.exports = function (options) {
  const { authServer, infoPath, userKey, emailKey, authArgs, clientSecret } = options;

  this.bindHook('third_login', async (ctx) => {
    const tokenEnc = ctx.request.body.token || ctx.request.query.token;
    const tokenEncBuf = Buffer.from(tokenEnc, 'base64');
    const iv = tokenEncBuf.slice(0, 12);
    const authTag = tokenEncBuf.slice(12, 12 + 16);
    const cipherText = tokenEncBuf.slice(12 + 16);
    const cipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(clientSecret, 'utf-8'), iv);
    cipher.setAuthTag(authTag);
    const result = [cipher.update(cipherText)];
    result.push(cipher.final());
    const token = Buffer.concat(result).toString('utf-8');

    try {
      const info = await axios.request({
        method: 'get',
        baseURL: authServer,
        url: infoPath,
        params: Object.assign({
          access_token: token
        }, authArgs)
      });

      if (info.status === 200) {
        return {
          username: gets(info.data, userKey),
          email: gets(info.data, emailKey)
        };
      } else {
        console.error('third_login.error', info)
        throw new Error(`${info.status} ${info.statusText}`)
      }
    } catch (error) {
      throw error
    }
  });

  this.bindHook('add_router', function (addRouter) {
    addRouter({
      controller: controller,
      method: 'get',
      path: 'oauth2/callback',
      action: 'oauth2Callback'
    });
  });
}
