#!/usr/bin/env node

var AWS = require('aws-sdk');
var http = require('http');
var httpProxy = require('http-proxy');
var express = require('express');
var bodyParser = require('body-parser');
var stream = require('stream');
var figlet = require('figlet');
var basicAuth = require('basic-auth-connect');
var compress = require('compression');
var aws4 = require('aws4');

var yargs = require('yargs')
    .usage('usage: $0 [options] <aws-es-cluster-endpoint>')
    .option('b', {
        alias: 'bind-address',
        default: process.env.BIND_ADDRESS || '127.0.0.1',
        demand: false,
        describe: 'the ip address to bind to',
        type: 'string'
    })
    .option('p', {
        alias: 'port',
        default: process.env.PORT || 9200,
        demand: false,
        describe: 'the port to bind to',
        type: 'number'
    })
    .option('r', {
        alias: 'region',
        default: process.env.REGION,
        demand: false,
        describe: 'the region of the Elasticsearch cluster',
        type: 'string'
    })
    .option('u', {
      alias: 'user',
      default: process.env.USER,
      demand: false,
      describe: 'the username to access the proxy'
    })
    .option('a', {
      alias: 'password',
      default: process.env.PASSWORD,
      demand: false,
      describe: 'the password to access the proxy'
    })
    .option('s', {
      alias: 'silent',
      default: false,
      demand: false,
      describe: 'remove figlet banner'
    })
    .option('l', {
      alias: 'limit',
      default: process.env.LIMIT || '1kb',  
      demand: false,
      describe: 'request limit'
    })
    .help()
    .version()
    .strict();
var argv = yargs.argv;

var ENDPOINT = process.env.ENDPOINT || argv._[0];

if (!ENDPOINT) {
    yargs.showHelp();
    process.exit(1);
}

// Try to infer the region if it is not provided as an argument.
var REGION = argv.r;
if (!REGION) {
    var m = ENDPOINT.match(/\.([^.]+)\.es\.amazonaws\.com\.?$/);
    if (m) {
        REGION = m[1];
    } else {
        console.error('region cannot be parsed from endpoint address, either the endpoint must end ' +
                      'in .<region>.es.amazonaws.com or --region should be provided as an argument');
        yargs.showHelp();
        process.exit(1);
    }
}

var TARGET = process.env.ENDPOINT || argv._[0];
if (!TARGET.match(/^https?:\/\//)) {
    TARGET = 'https://' + TARGET;
}

var BIND_ADDRESS = argv.b;
var PORT = argv.p;
var REQ_LIMIT = argv.l;

var credentials;
var chain = new AWS.CredentialProviderChain();
chain.resolve(function (err, resolved) {
    if (err) throw err;
    else credentials = resolved;
});

function getCredentials(req, res, next) {
    return credentials.get(function (err) {
        if (err) return next(err);
        else return next();
    });
}
var proxy = httpProxy.createProxyServer({
    target: TARGET,
    changeOrigin: true,
    secure: true
});

var app = express();
app.use(compress());
if (argv.u && argv.a) {
  app.use(basicAuth(argv.u, argv.a));
}
// app.use(bodyParser.raw({limit: REQ_LIMIT, type: function() { return true; }}));
app.use(bodyParser.text( {limit: '50mb', type: function() { return true; }} ));
app.use(getCredentials);
app.use(function (req, res) {
    proxy.web(req, res);
});

proxy.on('proxyReq', function (proxyReq, req) {

    var awsOptions = {
        method: proxyReq.method,
        path: proxyReq.path,
        region: REGION,
        host: 'search-cannalogue-app-dev-zokdboiwmijzfryxmglzqv3wvu.us-east-1.es.amazonaws.com',
        service: 'es'
    }

    if (req.headers && req.headers['content-type']) {
        awsOptions.headers = {
            'Content-Type' : req.headers['content-type'],
            'kbn-version' : req.headers['kbn-version']
        };
    }
    if (req.body && typeof req.body === "string" ) { 
        awsOptions.body = req.body;
    }

    // console.log("proxyReq BODY: ", proxyReq.body);

    aws4.sign(awsOptions, {accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY}) // assumes AWS credentials are available in process.env

    // console.log(awsOptions);

    // var endpoint = new AWS.Endpoint(ENDPOINT);
    // var request = new AWS.HttpRequest(endpoint);
    // request.method = proxyReq.method;
    // request.path = proxyReq.path;
    // request.region = REGION;
    // if (Buffer.isBuffer(req.body)) request.body = req.body;
    // if (!request.headers) request.headers = {};
    // request.headers['presigned-expires'] = false;
    // request.headers['Host'] = ENDPOINT;

    // var signer = new AWS.Signers.V4(request, 'es');
    // signer.addAuthorization(credentials, new Date());

    // proxyReq.setHeader('Host', request.headers['Host']);
    // proxyReq.setHeader('X-Amz-Date', request.headers['X-Amz-Date']);
    // proxyReq.setHeader('Authorization', request.headers['Authorization']);

    for( let key in awsOptions.headers) {
        // console.log(key, awsOptions.headers[key]);
        proxyReq.setHeader(key, awsOptions.headers[key]);
    }

    if (req.body && typeof req.body === "string" ) { 
        proxyReq.write(req.body);
        proxyReq.end();
    }

});

proxy.on('proxyRes', function (proxyReq, req, res) {
    if (req.url.match(/\.(css|js|img|font)/)) {
        res.setHeader('Cache-Control', 'public, max-age=86400');
    }
});

http.createServer(app).listen(PORT, BIND_ADDRESS);

if(!argv.s) {
    console.log(figlet.textSync('AWS ES Proxy!', {
        font: 'Speed',
        horizontalLayout: 'default',
        verticalLayout: 'default'
    }));
}

console.log('AWS ES cluster available at http://' + BIND_ADDRESS + ':' + PORT);
console.log('Kibana available at http://' + BIND_ADDRESS + ':' + PORT + '/_plugin/kibana/');
