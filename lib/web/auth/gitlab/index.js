'use strict'

const Router = require('express').Router
const passport = require('passport')
const GitlabStrategy = require('passport-gitlab2').Strategy
const config = require('../../../config')
const logger = require('../../../logger')
const response = require('../../../response')
const models = require('../../../models')
const { setReturnToFromReferer } = require('../utils')

const passportGeneralCallback = function callback (accessToken, refreshToken, profile, done) {
  var stringifiedProfile = JSON.stringify(profile)

  //logger.info("profile.email: " + profile._json.email)
  
  models.User.findOrCreate({
    where: {
      profileid: profile.id.toString()
    },
    defaults: {
      profile: stringifiedProfile,
      accessToken: accessToken,
      refreshToken: refreshToken,
      email: profile._json.email.email
    }
  }).spread(function (user, created) {
    if (user) {
      var needSave = false
      if (user.profile !== stringifiedProfile) {
        user.profile = stringifiedProfile
        needSave = true
      }
      if (user.accessToken !== accessToken) {
        user.accessToken = accessToken
        needSave = true
      }
      if (user.refreshToken !== refreshToken) {
        user.refreshToken = refreshToken
        needSave = true
      }
      if (user.email !== profile._json.email) {
        user.email = profile._json.email
        needSave = true
      }
      if (needSave) {
        user.save().then(function () {
          if (config.debug) { logger.info('user login: ' + user.id) }
          return done(null, user)
        })
      } else {
        if (config.debug) { logger.info('user login: ' + user.id) }
        return done(null, user)
      }
    }
  }).catch(function (err) {
    logger.error('auth callback failed: ' + err)
    return done(err, null)
  })
}

let gitlabAuth = module.exports = Router()

passport.use(new GitlabStrategy({
  baseURL: config.gitlab.baseURL,
  clientID: config.gitlab.clientID,
  clientSecret: config.gitlab.clientSecret,
  scope: config.gitlab.scope,
  callbackURL: config.serverURL + '/auth/gitlab/callback'
}, passportGeneralCallback))

gitlabAuth.get('/auth/gitlab', function (req, res, next) {
  setReturnToFromReferer(req)
  passport.authenticate('gitlab')(req, res, next)
})

// gitlab auth callback
gitlabAuth.get('/auth/gitlab/callback',
  passport.authenticate('gitlab', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/'
  })
)

if (!config.gitlab.scope || config.gitlab.scope === 'api') {
  // gitlab callback actions
  gitlabAuth.get('/auth/gitlab/callback/:noteId/:action', response.gitlabActions)
}
