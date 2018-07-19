const nextApp = require('next');
const express = require('express');
const helmet = require('helmet');
const morgan = require('morgan');
const Raven = require('raven');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const passport = require('passport');
const {
  validateBody,
  validationCriterias,
  preservedUrls,
  validateUrl,
  cooldownCheck,
  malwareCheck,
} = require('./controllers/validateBodyController');
const auth = require('./controllers/authController');
const url = require('./controllers/urlController');
const config = require('./config');

require('./passport');

if (config.RAVEN_DSN) {
  Raven.config(config.RAVEN_DSN).install();
}
const catchErrors = fn => (req, res, next) =>
  fn(req, res, next).catch(err => {
    res.status(500).json({ error: 'Sorry an error ocurred. Please try again later.' });
    if (config.RAVEN_DSN) {
      Raven.captureException(err, {
        user: { email: req.user && req.user.email },
      });
    } else {
      throw new Error(err);
    }
  });

const port = Number(config.PORT) || 3000;
const dev = process.env.NODE_ENV !== 'production';
const app = nextApp({ dir: './client', dev });
const handle = app.getRequestHandler();

app.prepare().then(() => {
  const server = express();

  server.set('trust proxy', true);
  server.use(helmet());
  if (process.env.NODE_ENV !== 'production') {
    server.use(morgan('dev'));
  }
  server.use(cookieParser());
  server.use(bodyParser.json());
  server.use(bodyParser.urlencoded({ extended: true }));
  server.use(passport.initialize());
  server.use('/u', express.static('static'));

  server.use((req, res, next) => {
    req.realIp = req.headers['x-real-ip'] || req.connection.remoteAddress || '';
    return next();
  });

  server.use((req, res, next) => {
    const { headers, path } = req;
    if (
      headers.host !== config.DEFAULT_DOMAIN &&
      (path === '/u/' || preservedUrls.some(item => item === path.replace('/u/', '')))
    ) {
      return res.redirect(`http://${config.DEFAULT_DOMAIN + path}`);
    }
    return next();
  });

  /* View routes */
  server.get('/u/', (req, res) => app.render(req, res, '/'));
  server.get('/u/login', (req, res) => app.render(req, res, '/login'));
  server.get('/u/logout', (req, res) => app.render(req, res, '/logout'));
  server.get('/u/settings', (req, res) => app.render(req, res, '/settings'));
  server.get('/u/stats', (req, res) => app.render(req, res, '/stats', req.query));
  server.get('/u/terms', (req, res) => app.render(req, res, '/terms'));
  server.get('/u/report', (req, res) => app.render(req, res, '/report'));
  server.get('/u/reset-password/:resetPasswordToken?', catchErrors(auth.resetPassword), (req, res) =>
    app.render(req, res, '/u/reset-password', req.user)
  );
  server.get('/verify/:verificationToken?', catchErrors(auth.verify), (req, res) =>
    app.render(req, res, '/u/verify', req.user)
  );

  /* User and authentication */
  server.post('/u/api/auth/signup', validationCriterias, validateBody, catchErrors(auth.signup));
  server.post('/u/api/auth/login', validationCriterias, validateBody, auth.authLocal, auth.login);
  server.post('/u/api/auth/renew', auth.authJwt, auth.renew);
  server.post('/u/api/auth/changepassword', auth.authJwt, catchErrors(auth.changePassword));
  server.post('/u/api/auth/generateapikey', auth.authJwt, catchErrors(auth.generateApiKey));
  server.post('/u/api/auth/resetpassword', catchErrors(auth.requestPasswordReset));
  server.get('/u/api/auth/usersettings', auth.authJwt, auth.userSettings);

  /* URL shortener */
  server.post(
    '/u/api/url/submit',
    auth.authApikey,
    auth.authJwtLoose,
    catchErrors(auth.recaptcha),
    catchErrors(validateUrl),
    catchErrors(cooldownCheck),
    catchErrors(malwareCheck),
    catchErrors(url.urlShortener)
  );
  server.post('/u/api/url/deleteurl', auth.authApikey, auth.authJwt, catchErrors(url.deleteUrl));
  server.get('/u/api/url/geturls', auth.authApikey, auth.authJwt, catchErrors(url.getUrls));
  server.post('/u/api/url/customdomain', auth.authJwt, catchErrors(url.setCustomDomain));
  server.delete('/u/api/url/customdomain', auth.authJwt, catchErrors(url.deleteCustomDomain));
  server.get('/u/api/url/stats', auth.authApikey, auth.authJwt, catchErrors(url.getStats));
  server.post('/u/api/url/requesturl', catchErrors(url.goToUrl));
  server.get('/u/:id', catchErrors(url.goToUrl), (req, res) => {
    switch (req.pageType) {
      case 'password':
        return app.render(req, res, '/u/url-password', req.protectedUrl);
      case 'info':
      default:
        return app.render(req, res, '/u/url-info', req.urlTarget);
    }
  });

  server.get('*', (req, res) => handle(req, res));

  server.listen(port, err => {
    if (err) throw err;
    console.log(`> Ready on http://localhost:${port}`); // eslint-disable-line no-console
  });
});
