(function(module) {
	"use strict";

	/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 137)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

	// if dev environment or stage - TODO remove for production 
	// avoid self-signed SSL errors with oauth sequence
	var https = require('https');
	https.globalAgent.options.rejectUnauthorized = false; // developer self signed cert workaround
	console.log('https.globalAgent', https.globalAgent);

	var User = module.parent.require('./user'),
		Groups = module.parent.require('./groups'),
		meta = module.parent.require('./meta'),
		db = module.parent.require('../src/database'),
		passport = module.parent.require('passport'),
		fs = module.parent.require('fs'),
		path = module.parent.require('path'),
		nconf = module.parent.require('nconf'),
		winston = module.parent.require('winston'),
		async = module.parent.require('async'),

		// make sure these are set in the config.json file under the oauth2keystone object: server, clientID, clientSecret
		oauthConfigs = nconf.get('oauth2keystone'),

		constants = Object.freeze({
			type: 'oauth2',	// Either 'oauth' or 'oauth2'
			name: 'ibm',	// Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
			oauth: {
				requestTokenURL: '',
				accessTokenURL: '',
				userAuthorizationURL: '',
				consumerKey: '',
				consumerSecret: ''
			},
			oauth2: {
				authorizationURL: oauthConfigs.server + 'oauth/authorise',
				tokenURL: oauthConfigs.server + 'oauth/token',
				clientID: oauthConfigs.clientID,
				clientSecret: oauthConfigs.clientSecret
			},
			scope: "profile",
			userRoute: oauthConfigs.server + 'oauth/profile',	// This is the address to your app's "user profile" API endpoint (expects JSON)
		}),
		configOk = false,
		OAuth = {}, passportOAuth, opts;

	if (!constants.name) {
		winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
	} else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
		winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
	} else if (!constants.userRoute) {
		winston.error('[sso-oauth] User Route required (library.js:31)');
	} else {
		configOk = true;
	}

	OAuth.getStrategy = function(strategies, callback) {
		if (configOk) {
			passportOAuth = require('passport-oauth')[constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy'];
			// console.log('a strategy oauth:', passportOAuth);
			// console.log('a strategy oauth:', passportOAuth);
			if (constants.type === 'oauth') {
				// OAuth options
				opts = constants.oauth;
				opts.callbackURL = nconf.get('NODEBB_SSO_CB_URL') + '/auth/' + constants.name + '/callback';

				passportOAuth.Strategy.prototype.userProfile = function(token, secret, params, done) {
					this._oauth.get(constants.userRoute, token, secret, function(err, body, res) {
						if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;
								done(null, profile);
							});
						} catch(e) {
							done(e);
						}
					});
				};
			} else if (constants.type === 'oauth2') {
				// OAuth 2 options
				opts = constants.oauth2;
				opts.callbackURL = nconf.get('NODEBB_SSO_CB_URL') + '/auth/' + constants.name + '/callback';

				passportOAuth.Strategy.prototype.userProfile = function(accessToken, done) {
					this._oauth2.get(constants.userRoute, accessToken, function(err, body, res) {
						if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

						try {
							var json = JSON.parse(body);
							OAuth.parseUserReturn(json, function(err, profile) {
								if (err) return done(err);
								profile.provider = constants.name;
								done(null, profile);
							});
						} catch(e) {
							done(e);
						}
					});
				};
			}
			var strategyInstance = new passportOAuth(opts, function(token, secret, profile, done) {
				OAuth.login({
					oAuthid: profile.id,
					handle: profile.displayName,
					email: profile.emails[0].value,
					isAdmin: profile.isAdmin,
					picture: profile.picture
				}, function(err, user) {
					if (err) {
						return done(err);
					}
					console.log('check user:', user);
					done(null, user);
				});
			});
			// console.log('strategyInstance:', strategyInstance);
			// console.log('strategyInstance:', strategyInstance._oauth2.ignoreCertificateVerification);

			passport.use(constants.name, strategyInstance);
			
			// passport.serializeUser(function(user, done) {
			// 	done(null, user.uid);
			// });

			// passport.deserializeUser(function(uid, done) {
			// 	done(null, {
			// 		uid: uid
			// 	});
			// });

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-check-square',
				scope: (constants.scope || '').split(',')
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.parseUserReturn = function(data, callback) {
		// Alter this section to include whatever data is necessary
		// NodeBB *requires* the following: id, displayName, emails.
		// Everything else is optional.

		// Find out what is available by uncommenting this line:
		// console.log(data);

		// console.log('checking serlializers:', passport._serializers);
		var profile = {};
		profile.id = data.profile._id;
		profile.displayName = data.profile.name.first + " " + data.profile.name.last;
		profile.emails = [{ value: data.profile.email }];
		profile.picture = data.profile.avatar.url;
		if (profile.picture) {
			if (profile.picture.indexOf('http') !== 0) {
				// prepend https: if not present
				profile.picture = "https:" + profile.picture;
			}
		}
		
		// console.log('saving profile:', profile);
		// Do you want to automatically make somebody an admin? This line might help you do that...
		// profile.isAdmin = data.isAdmin ? true : false;

		// Delete or comment out the next TWO (2) lines when you are ready to proceed
		// process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
		// return callback(new Error('Congrats! So far so good -- please see server log for details'));

		callback(null, profile);
	}

	OAuth.login = function(payload, callback) {
		console.log('OAuth.login:', payload);
		OAuth.getUidByOAuthid(payload.oAuthid, function(err, uid) {
			if(err) {
				return callback(err);
			}

			if (uid !== null) {
				// Existing User
				// console.log('is existing user...', uid, payload);
				OAuth.updateUserProfile(uid, payload);
				callback(null, {
					uid: uid
				});
			} else {
				// New User
				// console.log('creating new user:', payload);
				var success = function(uid) {
					// Save provider-specific information to the user
					User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					if (payload.isAdmin) {
						Groups.join('administrators', uid, function(err) {
							callback(null, {
								uid: uid
							});
						});
					} else {
						callback(null, {
							uid: uid
						});
					}
				};

				User.getUidByEmail(payload.email, function(err, uid) {
					if(err) {
						return callback(err);
					}

					if (!uid) {
						// console.log('user create go:', payload);
						User.create({
							username: payload.handle,
							email: payload.email
						}, function(err, uid) {
							if(err) {
								return callback(err);
							}
							// console.log('created:', err, uid);
							success(uid);
						});
					} else {
						// console.log("TODO merge oauth login profile with user:", payload);
						OAuth.updateUserProfile(uid, payload);
						success(uid); // Existing account -- merge that's a good idea hmmmm
					}
				});
			}
		});
	};

	OAuth.updateUserProfile = function(uid, payload) {
		if (payload.picture) {
			User.setUserFields(uid, {uploadedpicture: payload.picture, picture: payload.picture});	
		}
		
	}

	OAuth.getUidByOAuthid = function(oAuthid, callback) {

		db.getObjectField(constants.name + 'Id:uid', oAuthid, function(err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function(uid, callback) {
		async.waterfall([
			async.apply(User.getUserField, uid, constants.name + 'Id'),
			function(oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			}
		], function(err) {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + uid + '. Error: ' + err);
				return callback(err);
			}
			callback(null, uid);
		});
	};

	module.exports = OAuth;
}(module));
