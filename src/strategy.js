const OAuth2Strategy = require('passport-oauth2');
const util = require('util');
const querystring = require('querystring');
const crypto = require('crypto');
const request = require('request');

function Strategy(options, verify) {
  options = options || {};
  options.apiVersion = options.apiVersion || 'v1.0';
  options.authType = options.authType || 'sms_login';
  options.authorizationURL = options.authorizationURL || `https://www.accountkit.com/${options.apiVersion}/basic/dialog/${options.authType}`;
  options.tokenURL = options.tokenURL || `https://graph.accountkit.com/${options.apiVersion}/access_token`;

  OAuth2Strategy.call(this, options, verify);
  this.name = options.name || 'accountkit';
  this._userProfileURL = options.userProfileURL || `https://graph.accountkit.com/${options.apiVersion}/me`;
  this._baseUrl = options.baseUrl || '';

  this._oauth2.getOAuthAccessToken = function(code, params, callback) {
    params.code = code;
    delete params.redirect_uri;
    const query = querystring.stringify(params);

    this._request('GET', `${this._getAccessTokenUrl()}?${query}`, null, null, null, (error, data, response) => {
      if (error) { return callback(error); }

      const results = JSON.parse(data);
      const access_token = results.access_token;

      callback(null, access_token);
    });
  };
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken, done) {
  let self = this;

  const params = {
    access_token: accessToken,
    appsecret_proof: crypto.createHmac('sha256', this._oauth2._clientSecret).update(accessToken).digest('hex'),
  };

  const query = querystring.stringify(params);

  request(`${self._userProfileURL}?${query}`, (error, response, body) => {
    if (error) { return done(error); }

    let json;
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }
      
    let profile = JSON.parse(JSON.stringify(json));
    
    profile.provider = 'accountkit';
    profile._raw = body;
    profile._json = json;
    
    done(null, profile);
  });
};

Strategy.prototype.authorizationParams = function(options) {
  let params = {
    app_id: this._oauth2._clientId,
    fbAppEventsEnabled: false,
    state: Math.random().toString(36).substring(2),
    redirect: this._callbackURL,
  };
  
  return params;
};

Strategy.prototype.tokenParams = function(options) {
  let params = {
    access_token: `AA|${this._oauth2._clientId}|${this._oauth2._clientSecret}`,
  };

  return params;
};

module.exports = Strategy;
