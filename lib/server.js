var spdy = require('spdy'),
    http = require('http'),
    path = require('path'),
    util = require('util'),
    net = require('net'),
    url = require('url'),
    fs = require('fs'),
    stream = require('stream');
    
http.globalAgent.maxSockets = 128;

var cachingObjects = { };
var cachedHeaders = { };

var SPDYProxy = function(options) {
  var self = this;

  this.setAuthHandler = function(handler) {
    self._authHandler = handler;
    console.log('AuthHandler'.green, handler.friendly_name.yellow,
                'will be used.'.green);
  }

  this.setLogHandler = function(handler) {
    self._logHandler = handler;
    console.log('Requests will be logged into file'.green, handler._filename.yellow);
  }

  function logHeaders(headers) {
    for (var i in headers)
      console.log(' > '.grey + i.cyan + ': '.grey + headers[i]);
    console.log();
  }
  
  function logRequest(req) {
    console.log(req.method.green + ' ' + req.url.yellow);
    logHeaders(req.headers);
  }

  function synReply(socket, code, reason, headers, cb) {
    try {
      if (socket._handle instanceof spdy.handle) {
        var handle = socket._handle;
        handle._stream.respond(code, headers, function (err) {
          cb.call();
        });
          
      
      /*
      // SPDY socket
      if(socket._lock){
        socket._lock(function() {
          var socket = this;
          stream.respond(code, headers, function (err) {});
          this._spdyState.framer.replyFrame(
            this._spdyState.id, code, reason, headers,
            function (err, frame) {
              socket.connection.write(frame);
              socket._unlock();
              cb.call();
            }
          );
        });
        */

      // Chrome used raw SSL instead of SPDY when issuing CONNECT for
      // WebSockets. Hence, to support WS we must fallback to regular
      // HTTPS tunelling: https://github.com/igrigorik/node-spdyproxy/issues/26
      } else {
        console.log("Fallback for WebSockets");
        var statusLine = 'HTTP/1.1 ' + code + ' ' + reason + '\r\n';
        var headerLines = '';
        for(key in headers){
            headerLines += key + ': ' + headers[key] + '\r\n';
        }
        socket.write(statusLine + headerLines + '\r\n', 'UTF-8', cb);
      }
    } catch(error) {
      console.error("Error: ".red, error);
      console.error(error.stack);
      cb.call();
    }
  }

  function handlePlain(req, res) {
    var path = req.headers.path || url.parse(req.url).path;
    var requestOptions = {
      hostname: req.headers.host.split(':')[0],
      port: req.headers.host.split(':')[1] || 80,
      path: path,
      method: req.method,
      headers: req.headers
    };
    if (options.localAddress) {
      requestOptions.localAddress = options.localAddress;
    }

    // console.log('requests keys: ' + Object.keys(req));
    console.log('cached urls: ' + Object.keys(cachingObjects));
    if (req.url in cachingObjects) {
      // Return this object from the cache
      console.log('returning from cache'.green);
      console.log(cachingObjects[req.url].length);
      headers = cachedHeaders[req.url];
      var s = new stream.Readable();
      s._read = function noop() {}; // redundant? see update below
      // if (headers["content-type"].startsWith("image")) {
      //   s.push(cachingObjects[req.url].toString('binary'));
      // } else if (headers["content-tpye"] === "application/x-javascript") {
      //   s.push(cachingObjects[req.url].toString('utf-8'));
      // } else if (headers["content-encoding"] === "gzip") {
      //   s.push(cachingObjects[req.url].toString('binary'));
      // } else {
      //   s.push(cachingObjects[req.url].toString());
      // }
      s.push(cachingObjects[req.url].toString());
      s.push(null);
      console.log('Stream: ' + cachingObjects[req.url].length + ' headers: ' + Object.keys(cachedHeaders[req.url]) + ' content length: ' + cachedHeaders[req.url]['content-length']);
      // write out headers to handle redirects
      res.writeHead(200, '', cachedHeaders[req.url]);
      s.pipe(res);

      // Just in case if socket will be shutdown before http.request will connect
      // to the server.
      res.on('close', function() {
        s.unpipe();
        console.log('after cache');
      });

      return;
    } 
    if ('/.a/1.236.1/js/cnn-header-first.min.js' in cachingObjects) {
      console.log('content /.a/1.236.1/js/cnn-header-first.min.js: ' + cachingObjects['/.a/1.236.1/js/cnn-header-first.min.js'].length);
    }

    var rreq = http.request(requestOptions, function(rres) {
      rres.headers['proxy-agent'] = 'SPDY Proxy ' + options.version;

      if (options.verbose) {
        console.log("HTTP/" + rres.httpVersion + " " + rres.statusCode);
        logHeaders(rres.headers);
      }

      // remove invalid headers
      delete rres.headers["connection"];
      delete rres.headers["keep-alive"];
      delete rres.headers["proxy-connection"];

      // Force the caching policy.
      delete rres.headers["cache-control"];
      delete rres.headers["pragma"];
      delete rres.headers["etag"];
      delete rres.headers["last-modified"];
      delete rres.headers["date"];
      rres.headers["cache-control"] = "max-age=604800";
      cachedHeaders[req.url] = rres.headers;

      // if (!rres.headers["content-type"].startsWith("text")) {
      //   rres.setEncoding('binary');
      // } else if (rres.headers["content-type"] === "application/javascript") {
      //   rres.setEncoding('utf-8');
      // }
      contentEncoding = "utf-8";
      if (rres.headers["content-type"].startsWith("image") || rres.headers["content-encoding"] === "gzip") {
        contentEncoding = "binary";
      }
      if (!req.url in cachingObjects) {
        // When the object hasn't been cached yet. 
        if (req.url === '/.a/1.236.1/js/cnn-header-first.min.js') {
          console.log('\tinitial caching');
        }
        cachingObjects[req.url] = new Buffer('', contentEncoding);
      }

      // write out headers to handle redirects
      res.writeHead(rres.statusCode, rres.statusMessage || '', rres.headers);
      rres.pipe(res);

      // Res could not write, but it could close connection
      res.pipe(rres);

      rres.on('data', function(data) {
        // console.log('data');
        // console.log('url: ' + req.url + ' data len: ' + data.length);
        cachingObjects[req.url] += data;
        if (req.url === '/.a/1.236.1/js/cnn-header-first.min.js') {
          console.log('receiving data: ' + cachingObjects[req.url].length);
        }
      });
      rres.on('end', function() {
        console.log('finished url: ' + req.url);
        content_size = cachingObjects[req.url].length;
        console.log ('Cached header urls: ' + Object.keys(cachedHeaders));
        header_size = JSON.stringify(cachedHeaders[req.url]).length;
        total_size = content_size + header_size;
        console.log('object size: ' + content_size);
        console.log('header size: ' + header_size);
        console.log('total size: ' + total_size);
        encoding = rres.encoding;
        // fs.writeFile('tmp/' + req.url.substring(1, req.url.length).replace('/', '_'), cachingObjects[req.url], 'binary', function(err) {
        //   if (err) {
        //     return console.log(err);
        //   }
        //   console.log("Saved!");
        // });
        
      });
    });


    rreq.on('error', function(e) {
      console.log("Client error: " + e.message);
      res.writeHead(502, 'Proxy fetch failed');
      res.end("502 Proxy " + req.method + " failed: " + e.message);
    });

    req.pipe(rreq);

    // Just in case if socket will be shutdown before http.request will connect
    // to the server.
    res.on('close', function() {
      rreq.abort();
      console.log('aborted: ' + req.url);
    });
  }

  function handleSecure(req, socket) {
    var requestOptions = {
      host: req.headers.host.split(':')[0],
      port: req.headers.host.split(':')[1] || 443,
    };
    // var requestOptions = {
    //   host: req.url.split(':')[0],
    //   port: req.url.split(':')[1] || 443,
    // };
    if (options.localAddress) {
      requestOptions.localAddress = options.localAddress;
    }

    var tunnel = net.createConnection(requestOptions, function() {
      synReply(socket, 200, 'Connection established',
        {
          'Connection': 'keep-alive',
          'Proxy-Agent': 'SPDY Proxy ' + options.version,
          'cache-control': 'max-age=604800'
        },
        function() {
          tunnel.pipe(socket);
          socket.pipe(tunnel);
        }
      );
    });

    tunnel.setNoDelay(true);
    tunnel.setKeepAlive(true, 2000);
    tunnel.maxConnections = 1000;

    tunnel.on('error', function(e) {
      console.log("Tunnel error: ".red + e);
      synReply(socket, 502, "Tunnel Error", {}, function() {
        socket.end();
      });
    });
  }

  function handleRequest(req, res) {
    var socket = (req.method == 'CONNECT') ? res : res.socket;
    console.log("%s:%s".yellow + " - %s - " + "stream ID: " + "%s".yellow + " - priority: " + "%s".yellow,
      socket.connection ? socket.connection.socket.remoteAddress : socket.remoteAddress,
      socket.connection ? socket.connection.socket.remotePort : socket.remotePort,
      req.method, res.id || (socket._spdyState && socket._spdyState.id) || "none",
      res.priority || (socket._spdyState && socket._spdyState.priority) || "none"
    );

    // node-spdy forces chunked-encoding processing on inbound
    // requests without a content-length. However, we don't want
    // want to pass this injected header through to the destination.
    delete req.headers['transfer-encoding'];
    
    // Delete the cache control header from the browser.
    delete req.headers['cache-control'];
    delete req.headers['pragma'];

    var dispatcher = function(req, res) {
      req.method == 'CONNECT' ? handleSecure(req, res) : handlePlain(req, res);
    }

    if (options.verbose) logRequest(req);

    if(typeof self._logHandler == 'object') {
      self._logHandler.log(socket, req);
    }

    if(typeof self._authHandler == 'object') { // an AuthHandler is defined
      // perform basic proxy auth (over established SSL tunnel)
      // - http://www.chromium.org/spdy/spdy-authentication
      var header = req.headers['proxy-authorization'] || '',
          token = header.split(/\s+/).pop() || '',
          auth = new Buffer(token, 'base64').toString(),
          parts = auth.split(/:/),
          username = parts[0],
          password = parts[1];

      // don't pass proxy-auth headers upstream
      delete req.headers['proxy-authorization'];

      self._authHandler.authUser(username, password, function(authPassed) {
        if (authPassed)
          return dispatcher(req, res);

        synReply(socket, 407, 'Proxy Authentication Required',
          {'proxy-authenticate': 'Basic realm="SPDY Proxy"'},
          function() {
            socket.end();
          }
        );
      });
    } else { // auth is not necessary, simply go ahead and dispatch to funcs
      dispatcher(req, res);
    }

  }

  spdy.server.Server.call(this, options);

  this.on("connect", handleRequest);
  this.on("request", handleRequest);
};

util.inherits(SPDYProxy, spdy.server.Server);

var createServer = function(options) {
  return new SPDYProxy(options);
};

exports.SPDYProxy = SPDYProxy;
exports.createServer = createServer;
