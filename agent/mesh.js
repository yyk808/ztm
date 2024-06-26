import db from './db.js'

export default function (config) {
  var meshName = config.name
  var username
  var caCert
  var agentCert
  var agentKey
  var agentLog = []
  var meshErrors = []
  var services = []
  var ports = {}
  var exited = false

  if (config.ca) {
    try {
      caCert = new crypto.Certificate(config.ca)
    } catch {
      meshError('Invalid CA certificate')
    }
  } else {
    meshError('Missing CA certificate')
  }

  if (config.agent.certificate) {
    try {
      agentCert = new crypto.Certificate(config.agent.certificate)
      username = agentCert.subject?.commonName
    } catch {
      meshError('Invalid agent certificate')
    }
  } else {
    meshError('Missing agent certificate')
  }

  if (config.agent.privateKey) {
    try {
      agentKey = new crypto.PrivateKey(config.agent.privateKey)
    } catch {
      meshError('Invalid agent private key')
    }
  } else {
    meshError('Missing agent private key')
  }

  var tlsOptions = {
    certificate: agentCert && agentKey ? {
      cert: agentCert,
      key: agentKey,
    } : null,
    trusted: caCert ? [caCert] : null,
  }

  var hubAddresses = config.bootstraps.map(
    function (addr) {
      if (addr.startsWith('localhost:')) addr = '127.0.0.1:' + addr.substring(10)
      return addr
    }
  )

  //
  // Utility pipelies
  //

  var bypass = pipeline($ => $)

  var wrapUDP = pipeline($ => $
    .replaceData(data => data.size > 0 ? new Message(data) : undefined)
    .encodeWebSocket()
  )

  var unwrapUDP = pipeline($ => $
    .decodeWebSocket()
    .replaceMessage(msg => msg.body)
  )

  //
  // Class Hub
  // Management of the interaction with a single hub instance
  //

  function Hub(address) {
    var connections = new Set
    var holes = {}
    var closed = false
    var serviceList = null
    var serviceListUpdateTime = 0
    var serviceListSendTime = 0

    //
    //    requestHub ---\
    //                   \-->
    //                        hubSession <---> Hub
    //                   /---
    // reverseServer <--/
    //

    var $response
    var $serviceListTime

    // Long-lived agent-to-hub connection, multiplexed with HTTP/2
    var hubSession = pipeline($ => $
      .muxHTTP(() => '', { version: 2 }).to($ => $
        .connectTLS({
          ...tlsOptions,
          onState: (session) => {
            var err = session.error
            if (err) meshError(err)
          }
        }).to($ => $
          .onStart(() => { meshErrors.length = 0 })
          .connect(address, {
            onState: function (conn) {
              if (conn.state === 'connected') {
                logInfo(`Connected to hub ${address}`)
                meshErrors.length = 0
                connections.add(conn)
                if (serviceList) updateServiceList(serviceList)
              } else if (conn.state === 'closed') {
                connections.delete(conn)
              }
            }
          })
          .handleStreamEnd(
            (eos) => meshError(`Connection to hub ${address} closed, error = ${eos.error}`)
          )
        )
      )
    )

    // Send a request to the hub
    var requestHub = pipeline($ => $
      .onStart(msg => msg)
      .pipe(hubSession)
      .handleMessage(msg => $response = msg)
      .replaceMessage(new StreamEnd)
      .onEnd(() => $response)
    )

    // Hook up to the hub and receive orders
    var reverseServer = pipeline($ => $
      .onStart(new Data)
      .repeat(() => new Timeout(5).wait().then(() => !closed)).to($ => $
        .loop($ => $
          .connectHTTPTunnel(
            new Message({
              method: 'CONNECT',
              path: `/api/endpoints/${config.agent.id}`,
            })
          )
          .to(hubSession)
          .pipe(serveHub)
        )
      )
    )

    // Establish a pull session to the hub
    reverseServer.spawn()

    // Start sending service list updates
    pipeline($ => $
      .onStart(new Data)
      .repeat(() => new Timeout(1).wait().then(() => !closed)).to($ => $
        .forkJoin().to($ => $
          .pipe(
            () => {
              if (serviceListUpdateTime > serviceListSendTime) {
                $serviceListTime = serviceListUpdateTime
                return 'send'
              }
              return 'wait'
            }, {
            'wait': ($ => $.replaceStreamStart(new StreamEnd)),
            'send': ($ => $.replaceStreamStart(
              () => requestHub.spawn(
                new Message(
                  {
                    method: 'POST',
                    path: `/api/services`,
                  },
                  JSON.encode({
                    time: $serviceListTime,
                    services: serviceList || [],
                  })
                )
              ).then(
                function (res) {
                  if (res && res.head.status === 201) {
                    if (serviceListSendTime < $serviceListTime) {
                      serviceListSendTime = $serviceListTime
                    }
                  }
                  return new StreamEnd
                }
              )
            )),
          }
          )
        )
        .replaceStreamStart(new StreamEnd)
      )
    ).spawn()

    function updateServiceList(list) {
      serviceList = list
      serviceListUpdateTime = Date.now()
    }

    function updateHoles() {
      holes.forEach((key, hole) => {
        if (hole.state === 'fail') delete holes[key]
      })
    }

    function heartbeat() {
      if (closed) return
      requestHub.spawn(
        new Message(
          { method: 'POST', path: '/api/status' },
          JSON.encode({ name: config.agent.name })
        )
      )
    }

    function createHole(epName, proto, svcName) {
      var key = holeName(epName, proto, svcName)
      var svc = findService(proto, svcName)
      var hole = Hole(epName, svc, key)

      if (hole.state != 'fail') {
        holes[key] = hole
        return hole
      }

      return null
    }

    function advertiseFilesystem(files) {
      filesystemLatest = files
      filesystemUpdate = files
    }

    function discoverEndpoints() {
      return requestHub.spawn(
        new Message({ method: 'GET', path: '/api/endpoints' })
      ).then(
        function (res) {
          if (res && res.head.status === 200) {
            return JSON.decode(res.body)
          } else {
            return []
          }
        }
      )
    }

    function discoverServices(ep) {
      return requestHub.spawn(
        new Message({ method: 'GET', path: ep ? `/api/endpoints/${ep}/services` : '/api/services' })
      ).then(
        function (res) {
          if (res && res.head.status === 200) {
            return JSON.decode(res.body)
          } else {
            return []
          }
        }
      )
    }

    function findEndpoint(ep) {
      return requestHub.spawn(
        new Message({ method: 'GET', path: `/api/endpoints/${ep}` })
      ).then(
        function (res) {
          if (res && res.head.status === 200) {
            return JSON.decode(res.body)
          } else {
            return null
          }
        }
      )
    }

    function findService(proto, svc) {
      return requestHub.spawn(
        new Message({ method: 'GET', path: `/api/services/${proto}/${svc}` })
      ).then(
        function (res) {
          if (res && res.head.status === 200) {
            return JSON.decode(res.body)
          } else {
            return null
          }
        }
      )
    }

    function findHole(ep, proto, svcName) {
      var key = holeName(ep, proto, svcName)
      return holes[key]
    }

    function leave() {
      closed = true
      connections.forEach(
        conn => conn.close()
      )
      holes.forEach(
        (_, hole) => hole.leave()
      )
    }

    return {
      isConnected: () => connections.size > 0,
      address,
      holes,
      createHole,
      heartbeat,
      updateServiceList,
      updateHoles,
      discoverEndpoints,
      discoverServices,
      findEndpoint,
      findService,
      findHole,
      leave,
    }

  } // End of class Hub

  // Only available for symmetric NAT
  function Hole(ep, svc, holeName) {
    // TODO: Hole should be bound to ep not svc
    var bound = '0.0.0.0:' + randomPort()   // local port that the hole using
    var destIP                              // dest ip out of NAT
    var destPort                            // dest port out of NAT
    var role = null                         // server or client
    var proto = svc.protocol

    // closed forwarding connecting(ready punching) connected fail
    var state = 'closed'
    var $hubConnection = null
    var $connection = null
    var $hub = hubs[0]
    var $pHub = new pipeline.Hub
    var $session
    var $hubResponse

    // A temp tunnel to help hub gather NAT info.
    var hubSession = pipeline($ => $
      .muxHTTP(() => holeName + "hub", { version: 2 }).to($ => $
        .connectTLS({
          ...tlsOptions,
          onState: (session) => {
            var err = session.error
            if (err) state = 'fail'
          }
        }).to($ => $
          .connect($hub.address, {
            onState: function (conn) {
              $hubConnection = conn
              if (conn.state === 'open') {
                // SOL_SOCKET & SO_REUSEPORT
                conn.socket.setRawOption(1, 15, new Data([1]))
              }

              if (conn.state === 'connected' && state === 'closed') {
                state = 'forwarding'
                reverseServer.spawn()
              }
            },
            bind: bound,
          })
        )
      )
    )

    var reverseServer = pipeline($ => $
      .onStart(new Data)
      .repeat(() => new Timeout(5).wait().then(() => {
        if (state != 'forwarding') {
          $hubConnection.close()
          return false
        }
        return true
      })).to($ => $
        .loop($ => $
          .connectHTTPTunnel(
            new Message({
              method: 'CONNECT',
              path: `/api/endpoints/${config.agent.id}`,
            })
          )
          .to(hubSession)
          .pipe(servePunch)
        )
      )
    )

    var servePunch = pipeline($ => $
      .demuxHTTP().to($ => $.pipe(() => {
        var routes = Object.entries({
          '/api/punch/{ep}/{proto}/{svc}/sync': {
            // Hub sent synchronize message. Once receive, start punch.
            // Agent <- Hub -> Remote Agent.
            'POST': function (params, req) {
              var body = JSON.decode(req.body)
              destIP = body.dstIP
              destPort = body.port
              state = 'ready'

              punch()
            }
          },
        }).map(function ([path, methods]) {
          var match = new http.Match(path)
          var handler = function (params, req) {
            var f = methods[req.head.method]
            if (f) return f(params, req)
            return response(405)
          }
          return { match, handler }
        })

        return pipeline($ => $
          .replaceMessage(
            function (req) {
              var params
              var path = req.head.path
              var route = routes.find(r => Boolean(params = r.match(path)))
              if (route) {
                try {
                  var res = route.handler(params, req)
                  return res instanceof Promise ? res.catch(responseError) : res
                } catch (e) {
                  return responseError(e)
                }
              }
              meshError('Invalid api call from hub')
              return response(404)
            }
          )
        )
      }
      ))
    )

    function directSession() {
      // TODO !!! state error would happen when network is slow
      // must handle this

      if (!role) meshError('Hole not init correctly')
      if ($session) return $session

      // TODO: support TLS connection
      if (role === 'client') {
        // make session to server side directly
        $session = pipeline($ => $
          .muxHTTP(() => holeName + "direct", { version: 2 }).to($ => $
            .connect(`${destIP}:${destPort}`, {
              onState: function (conn) {
                if (conn.state === 'open') {
                  conn.socket.setRawOption(1, 15, new Data([1]))
                } else if (conn.state === 'connected') {
                  logInfo(`Connected to remote ${destIP}:${destPort}`)
                  $connection = conn
                  state = 'connected'
                } else if (conn.state === 'closed') {
                  logInfo(`Disconnected from remote ${destIP}:${destPort}`)
                  $connection = null
                  state = 'closed'
                }
              },
              bind: bound
            })
          )
        )

        // reverse server for receiving requests
        pipeline($ => $
          .onStart(new Data)
          .repeat(() => new Timeout(5).wait().then(() => {
            return state != 'fail' || state != 'closed'
          })).to($ => $
            .loop($ => $
              .connectHTTPTunnel(
                new Message({
                  method: 'CONNECT',
                  path: `/api/punch/${ep}/${proto}/${svc.name}`,
                })
              )
              .to($session)
              .pipe(serveHub)
            )
          )
        ).spawn()

      } else if (role === 'server') {
        pipy.listen(bound, 'tcp', serveHub)

        $session = pipeline($ => $
          .muxHTTP(() => holeName + "direct", { version: 2 }).to($ => $
            .swap(() => $pHub)
          )
        )
      }

      return $session
    }

    // use THE port sending request to hub.
    function requestPunch() {
      // FIXME: add state check
      state = 'connecting'
      role = 'client'

      pipeline($ => $
        .onStart(new Message({
          method: 'GET',
          path: `/api/punch/${ep}/${proto}/${svc}/request`,
        }))
        .pipe(hubSession)
        .handleMessage(msg => $hubResponse = msg)
        .replaceMessage(new StreamEnd)
        .onEnd(() => $hubResponse)
      ).spawn()
    }

    // TODO add cert info into response
    function acceptPunch() {
      state = 'connecting'
      role = 'server'

      pipeline($ => $
        .onStart(new Message({
          method: 'POST',
          path: `/api/punch/${ep}/${proto}/${svc}/reqeust`,
        }))
        .pipe(hubSession)
        .handleMessage(msg => $hubResponse = msg)
        .replaceMessage(new StreamEnd)
        .onEnd(() => $hubResponse)
      ).spawn()
    }

    function punch(destIP, destPort) {
      // receive TLS options
      // connectTLS
      // connectLocal or connectRemote

      // TODO add retry logic here
      state = 'punching'
      makeFakeCall(destIP, destPort)
      $session = directSession()
      heartbeat() // activate the session pipeline
    }

    function makeRespTunnel() {
      // TODO add state check
      state = 'connected'

      return pipeline($ => $
        .acceptHTTPTunnel(() => response200()).to($ => $
          .onStart(new Data)
          .swap(() => $pHub)
          .onEnd(() => console.info(`Direct Connection from ${ep} lost`))
        )
      )
    }

    // send a SYN to dest, expect no return.
    // this will cheat the firewall to allow inbound connection from dest.
    function makeFakeCall(destIP, destPort) {
      pipy().task().onStart(new Data).connect(`${destIP}:${destPort}`, {
        bind: bound,
        onState: function (conn) {
          // REUSEPORT
          if (conn.state === 'open') conn.socket.setRawOption(1, 15, new Data([1]))

          // abort this connection.
          if (conn.state === 'connecting') conn.close()
        }
      })
    }


    function heartbeat() {
      // no need to do so
      if (role === 'server' || connectHub || state === 'failed') {
        return
      }

      // requestHub.spawn(
      //   new Message(
      //     { method: 'POST', path: '/api/status' },
      //     JSON.encode({ name: config.agent.name })
      //   )
      // )

    }

    function leave() {
      $hubConnection?.close()
      $connection?.close()
      $hubConnection = null
      $connection = null

      if(state != 'fail') state = 'closed'
      $hub.updateHoles()
    }

    return {
      state,
      isConnected,
      requestPunch,
      acceptPunch,
      punch,
      makeRespTunnel,
      directSession,
      heartbeat,
      leave,
    }
  } // End of Hole

  var matchServices = new http.Match('/api/services/{proto}/{svc}')
  var matchPunch = new http.Match('/api/punch/{ep}/{proto}/{svc}')
  var response200 = new Message({ status: 200 })
  var response404 = new Message({ status: 404 })

  var $requestedService
  var $selectedEp
  var $selectedHub

  //
  // Agent serving requests from the hubs
  //
  //   Hub ----\
  //   Hub -----)----> Agent
  //   Hub ----/
  //

  var serveHub = pipeline($ => $
    .demuxHTTP().to($ => $
      .pipe(
        function (evt) {
          if (evt instanceof MessageStart) {
            if (evt.head.method === 'CONNECT') {
              var svcParams = matchServices(evt.head.path)
              if (svcParams) return proxyToLocal

              var punchParams = matchPunch(evt.head.path)
              if (punchParams) {
                var hole = findHole(punchParams.ep, punchParams.proto, punchParams.svc)
                return hole.makeRespTunnel()
              }
            }
            return serveOtherAgents
          }
        }
      )
    )
  )

  //
  // Agent handling requests from other agents
  //
  //   Remote Agent ----> Hub ----\
  //   Remote Agent ---(directly)--)----> Agent
  //   Remote Agent ----> Hub ----/
  //

  var serveOtherAgents = (function () {
    var routes = Object.entries({

      '/api/ping': {
        'GET': () => response(200)
      },

      '/api/services': {
        'GET': function () {
          return response(200, db.allServices(meshName))
        },
      },

      '/api/services/{proto}/{svc}': {
        'GET': function () {
          return response(200, db.getService(meshName, params.proto, params.svc))
        },

        'POST': function (params, req) {
          db.setService(meshName, params.proto, params.svc, JSON.decode(req.body))
          var s = db.getService(meshName, params.proto, params.svc)
          publishService(params.proto, params.svc, s.host, s.port, s.users)
          return response(201, s)
        },

        'DELETE': function (params) {
          deleteService(params.proto, params.svc)
          db.delService(meshName, params.proto, params.svc)
          return response(204)
        },
      },

      '/api/ports': {
        'GET': function () {
          return response(200, db.allPorts(meshName).map(
            p => Object.assign(p, checkPort(p.listen.ip, p.protocol, p.listen.port))
          ))
        },
      },

      '/api/ports/{ip}/{proto}/{port}': {
        'GET': function (params) {
          var ip = params.ip
          var proto = params.proto
          var port = Number.parseInt(params.port)
          return response(200, Object.assign(
            db.getPort(meshName, ip, proto, port),
            checkPort(ip, proto, port),
          ))
        },

        'POST': function (params, req) {
          var port = Number.parseInt(params.port)
          var body = JSON.decode(req.body)
          var target = body.target
          openPort(params.ip, params.proto, port, target.service, target.endpoint)
          db.setPort(meshName, params.ip, params.proto, port, body)

          // request to punch a hole.
          var hole = hubs[0].createHole(target.endpoint, params.proto, target.svc)
          hole.requestPunch()

          return response(201, db.getPort(meshName, params.ip, params.proto, port))
        },

        'DELETE': function (params) {
          var port = Number.parseInt(params.port)
          closePort(params.ip, params.proto, port)
          db.delPort(meshName, params.ip, params.proto, port)
          return response(204)
        },
      },

      '/api/log': {
        'GET': function () {
          return response(200, getLog())
        }
      },

      '/api/punch/{ep}/{proto}/{svc}/request': {
        // handle punch hole request from peer or hub.
        // Agent ---> Hub ---> Service Publisher(Remote Agent)
        'GET': function (params) {
          var hole = hubs[0].createHole(params.ep, params.proto, params.svc)
          hole.acceptPunch()

          return response(200)
        },

        // 'POST': only implement on hub side.
        // Service Publisher -> Hub
      },

      '/api/file-data/{hash}': {
        'GET': function ({ hash }) {
          var data = fs.raw(hash)
          return data ? response(200, data) : response(404)
        },
      },

      '/api/apps': {
        'GET': function () {
          return discoverApps(config.agent.id).then(
            ret => response(200, ret)
          )
        }
      },

      '/api/apps/{provider}/{app}': {
        'GET': function ({ provider, app }) {
          return findApp(config.agent.id, provider, app).then(
            ret => ret ? response(200, ret) : response(404)
          )
        },

        'POST': function ({ provider, app }, req) {
          var ep = config.agent.id
          var state = JSON.decode(req.body)
          return findApp(ep, provider, app).then(ret => {
            if (!ret) return installApp(ep, provider, app)
          }).then(() => {
            if ('isRunning' in state) {
              if (state.isRunning) {
                apps.start(provider, app)
              } else {
                apps.stop(provider, app)
              }
            }
            return response(201)
          }).then(() => {
            if ('isPublished' in state) {
              if (state.isPublished) {
                return publishApp(ep, provider, app)
              } else {
                return unpublishApp(ep, provider, app)
              }
            }
          }).then(response(201))
        },

        'DELETE': function ({ provider, app }) {
          return uninstallApp(config.agent.id, provider, app).then(response(204))
        },
      },

    }).map(
      function ([path, methods]) {
        var match = new http.Match(path)
        var handler = function (params, req) {
          var f = methods[req.head.method]
          if (f) return f(params, req)
          return response(405)
        }
        return { match, handler }
      }
    )

    return pipeline($ => $
      .replaceMessage(
        function (req) {
          var params
          var path = req.head.path
          var route = routes.find(r => Boolean(params = r.match(path)))
          if (route) return route.handler(params, req)
          return response(404)
        }
      )
    )
  })()

  //
  // Agent proxying to local services: mesh -> local OR agent -> local(with hole punched)
  //
  //   Remote Client ----> Remote Agent ----> Hub ----\                  /----> Local Service
  //   Remote Client ----> Remote Agent ---------------)----> Agent ----(-----> Local Service
  //   Remote Client ----> Remote Agent ----> Hub ----/                  \----> Local Service
  //

  var proxyToLocal = pipeline($ => $
    .acceptHTTPTunnel(
      function (req) {
        var params = matchServices(req.head.path)
        if (params) {
          var protocol = params.proto
          var name = params.svc
          $requestedService = services.find(s => s.protocol === protocol && s.name === name)
          if ($requestedService) {
            logInfo(`Proxy to local service ${name}`)
            return response200
          }
          logError(`Local service ${name} not found`)
        }
        return response404
      }
    ).to($ => $
      .pipe(() => $requestedService.protocol, {
        'tcp': ($ => $.connect(() => `${$requestedService.host}:${$requestedService.port}`)),
        'udp': ($ => $
          .pipe(unwrapUDP)
          .connect(() => `${$requestedService.host}:${$requestedService.port}`, { protocol: 'udp' })
          .pipe(wrapUDP)
        )
      })
      .onEnd(() => logInfo(`Proxy to local service ${$requestedService.name} ended`))
    )
  )

  //
  // Agent proxying to remote services: local -> mesh
  //
  //   Local Client ----\                  /----> Hub ----> Remote Agent ----> Remote Service
  //   Local Client -----)----> Agent ----(-----> Hub ----> Remote Agent ----> Remote Service
  //   Local Client ----/                  \----> Hub ----> Remote Agent ----> Remote Service
  //

  var proxyToMesh = (proto, svc, ep) => pipeline($ => $
    .onStart(() => {
      if (ep) {
        $selectedEp = ep
        return selectHub(ep).then(hub => {
          $selectedHub = hub
          return new Data
        })
      } else {
        return selectEndpoint(proto, svc).then(ep => {
          if (!ep) return new Data
          $selectedEp = ep
          return selectHub(ep).then(hub => {
            $selectedHub = hub
            return new Data
          })
        })
      }
    })
    .pipe(() => $selectedHub ? 'proxy' : 'deny', {
      'proxy': ($ => $
        .onStart(() => logInfo(`Proxy to ${svc} at endpoint ${$selectedEp} via ${$selectedHub}`))
        .pipe(proto === 'udp' ? wrapUDP : bypass)
        .pipe(() => {
          var hole = findHole(ep, proto, svc)
          if (hole) return pipeline($ => $
            .connectHTTPTunnel(() => new Message({
              method: 'CONNECT',
              path: `/api/services/${proto}/${svc}`,
            })).to(hole.directSession())
          )
          return pipeline($ => $
            .connectHTTPTunnel(() => (
              new Message({
                method: 'CONNECT',
                path: `/api/endpoints/${$selectedEp}/services/${proto}/${svc}`,
              })
            )).to($ => $
              .muxHTTP(() => $selectedHub, { version: 2 }).to($ => $
                .connectTLS(tlsOptions).to($ => $
                  .connect(() => $selectedHub)
                )
              )
            )
          )
        })
        .pipe(proto === 'udp' ? unwrapUDP : bypass)
        .onEnd(() => logInfo(`Proxy to ${svc} at endpoint ${$selectedEp} via ${$selectedHub} ended`))
      ),
      'deny': ($ => $
        .onStart(() => logError($selectedEp ? `No route to endpoint ${$selectedEp}` : `No endpoint found for ${svc}`))
        .replaceData(new StreamEnd)
      ),
    })
  )

  // HTTP agents for ad-hoc agent-to-hub sessions
  var httpAgents = new algo.Cache(
    target => new http.Agent(target, { tls: tlsOptions })
  )

  // Connect to all hubs
  var hubs = config.bootstraps.map(
    addr => Hub(addr)
  )

  // Start sending heartbeats
  // TODO: add heartbeat for direct connections.
  heartbeat()
  function heartbeat() {
    if (!exited) {
      hubs.forEach(h => {
        h.heartbeat()
        h.holes.forEach((_, hole) => hole.heartbeat())
      })
      new Timeout(15).wait().then(heartbeat)
    }
  }

  // Publish services
  db.allServices(meshName).forEach(
    function (s) {
      publishService(s.protocol, s.name, s.host, s.port, s.users)
    }
  )

  // Open local ports
  db.allPorts(meshName).forEach(
    function (p) {
      var listen = p.listen
      var target = p.target
      openPort(listen.ip, p.protocol, listen.port, target.service, target.endpoint)
    }
  )

  logInfo(`Joined ${meshName} as ${config.agent.name} (uuid = ${config.agent.id})`)

  function selectEndpoint(proto, svc) {
    return hubs[0].findService(proto, svc).then(
      function (service) {
        if (!service) return null
        var ep = service.endpoints[0]
        return ep ? ep.id : null
      }
    )
  }

  function selectHub(ep) {
    return hubs[0].findEndpoint(ep).then(
      function (endpoint) {
        if (!endpoint) return null
        var addresses = endpoint.hubs || []
        return addresses.find(addr => hubAddresses.indexOf(addr) >= 0) || hubs[0].address
      }
    )
  }

  function selectHubWithThrow(ep) {
    return selectHub(ep).then(hub => {
      if (!hub) throw `No hub for endpoint ${ep}`
      return hub
    })
  }

  function findEndpoint(ep) {
    return hubs[0].findEndpoint(ep)
  }

  function findHole(ep, proto, svc) {
    return hubs[0].findHole(ep, proto, svc)
  }

  function findFile(pathname) {
    return hubs[0].findFile(pathname)
  }

  function findApp(ep, provider, app) {
    if (ep === config.agent.id) {
      var isInstalled = apps.list(provider).includes(app)
      var isPublished = Boolean(fs.stat(`/home/${provider}/apps/pkg/${app}`))
      if (isPublished || isInstalled) {
        return Promise.resolve({
          ...getAppNameTag(app),
          provider,
          isPublished,
          isRunning: false,
        })
      } else {
        return Promise.resolve(null)
      }
    } else {
      return selectHubWithThrow(ep).then(
        (hub) => httpAgents.get(hub).request(
          'GET', `/api/forward/${ep}/apps/${provider}/${app}`
        ).then(
          res => {
            return res.head?.status === 200 ? JSON.decode(res.body) : null
          }
        )
      )
    }
  }

  function discoverEndpoints() {
    return hubs[0].discoverEndpoints()
  }

  function discoverServices(ep) {
    return hubs[0].discoverServices(ep)
  }

  function publishService(protocol, name, host, port, users) {
    users = users || null
    var old = services.find(s => s.name === name && s.protocol === protocol)
    if (old) {
      old.host = host
      old.port = port
      old.users = users
    } else {
      services.push({
        name,
        protocol,
        host,
        port,
        users,
      })
    }
    updateServiceList()
  }

  function deleteService(protocol, name) {
    var old = services.find(s => s.name === name && s.protocol === protocol)
    if (old) {
      services.splice(services.indexOf(old), 1)
      updateServiceList()
    }
  }

  function updateServiceList() {
    var list = services.map(({ name, protocol, users }) => ({ name, protocol, users }))
    hubs.forEach(hub => hub.updateServiceList(list))
  }

  function portName(ip, protocol, port) {
    return `${ip}/${protocol}/${port}`
  }

  // considering NAT, ip & port pair isn't strong enough to be distinguished.
  function holeName(ep, protocol, svcName) {
    return `${ep}/${protocol}/${svcName}`
  }

  function openPort(ip, protocol, port, service, endpoint) {
    var key = portName(ip, protocol, port)
    var p = ports[key]
    try {
      switch (protocol) {
        case 'tcp':
        case 'udp':
          if (p && p.open) {
            // FIXME only close port when hole punched successfully.
            closePort(ip, protocol, port) // should it be closed?
          } else {
            pipy.listen(`${ip}:${port}`, protocol, proxyToMesh(protocol, service, endpoint))
          }
          break
        default: throw `Invalid protocol: ${protocol}`
      }
      ports[key] = { open: true }
    } catch (err) {
      ports[key] = { open: false, error: err.toString() }
    }
  }

  function closePort(ip, protocol, port) {
    var key = portName(ip, protocol, port)
    pipy.listen(`${ip}:${port}`, protocol, null)
    delete ports[key]
  }

  function checkPort(ip, protocol, port) {
    var key = portName(ip, protocol, port)
    return ports[key]
  }

  function randomPort() {
    return Number.parseInt(Math.random() * (65535 - 1024)) + 1024
  }

  function remoteQueryServices(ep) {
    return selectHubWithThrow(ep).then(
      (hub) => httpAgents.get(hub).request(
        'GET', `/api/forward/${ep}/services`
      ).then(
        res => {
          remoteCheckResponse(res, 200)
          return JSON.decode(res.body)
        }
      )
    )
  }

  function remotePublishService(ep, proto, name, host, port, users) {
    return selectHubWithThrow(ep).then(
      (hub) => httpAgents.get(hub).request(
        'POST', `/api/forward/${ep}/services/${proto}/${name}`,
        {}, JSON.encode({ host, port, users })
      ).then(
        res => {
          remoteCheckResponse(res, 201)
          return JSON.decode(res.body)
        }
      )
    )
  }

  function remoteDeleteService(ep, proto, name) {
    return selectHubWithThrow(ep).then(
      (hub) => httpAgents.get(hub).request(
        'DELETE', `/api/forward/${ep}/services/${proto}/${name}`
      ).then(
        res => {
          remoteCheckResponse(res, 204)
        }
      )
    )
  }

  function remoteQueryPorts(ep) {
    return selectHubWithThrow(ep).then(
      (hub) => httpAgents.get(hub).request(
        'GET', `/api/forward/${ep}/ports`
      ).then(
        res => {
          remoteCheckResponse(res, 200)
          return JSON.decode(res.body)
        }
      )
    )
  }

  function remoteOpenPort(ep, ip, proto, port, target) {
    return selectHubWithThrow(ep).then(
      (hub) => httpAgents.get(hub).request(
        'POST', `/api/forward/${ep}/ports/${ip}/${proto}/${port}`,
        {}, JSON.encode({ target })
      ).then(
        res => {
          remoteCheckResponse(res, 201)
          return JSON.decode(res.body)
        }
      )
    )
  }

  function remoteClosePort(ep, ip, proto, port) {
    return selectHubWithThrow(ep).then(
      (hub) => httpAgents.get(hub).request(
        'DELETE', `/api/forward/${ep}/ports/${ip}/${proto}/${port}`
      ).then(
        res => {
          remoteCheckResponse(res, 204)
        }
      )
    )
  }

  function remoteQueryLog(ep) {
    return selectHubWithThrow(ep).then(
      (hub) => httpAgents.get(hub).request(
        'GET', `/api/forward/${ep}/log`
      ).then(
        res => {
          remoteCheckResponse(res, 200)
          return JSON.decode(res.body)
        }
      )
    )
  }

  function remoteCheckResponse(res, expected) {
    var status = res?.head?.status
    if (status !== expected) {
      throw { status: status || 500, message: res?.head?.statusText }
    }
  }

  function leave() {
    db.allPorts(meshName).forEach(
      function ({ protocol, listen }) {
        closePort(listen.ip, protocol, listen.port)
      }
    )
    hubs.forEach(hub => hub.leave())
    exited = true
    logInfo(`Left ${meshName} as ${config.agent.name} (uuid = ${config.agent.id})`)
  }

  function isConnected() {
    return hubs.some(h => h.isConnected())
  }

  function getStatus() {
    return {
      name: meshName,
      ca: config.ca,
      agent: {
        id: config.agent.id,
        name: config.agent.name,
        username,
        certificate: config.agent.certificate,
      },
      bootstraps: [...config.bootstraps],
      connected: isConnected(),
      errors: getErrors(),
    }
  }

  function getLog() {
    return [...agentLog]
  }

  function getErrors() {
    return [...meshErrors]
  }

  function log(type, msg) {
    if (agentLog.length > 100) {
      agentLog.splice(0, agentLog.length - 100)
    }
    agentLog.push({
      time: new Date().toISOString(),
      type,
      message: msg,
    })
  }

  function logInfo(msg) {
    log('info', msg)
    console.info(msg)
  }

  function logError(msg) {
    log('error', msg)
    console.error(msg)
  }

  function meshError(msg) {
    logError(msg)
    meshErrors.push({
      time: new Date().toISOString(),
      message: msg,
    })
  }

  return {
    config,
    username,
    isConnected,
    getStatus,
    getLog,
    getErrors,
    findEndpoint,
    discoverEndpoints,
    discoverServices,
    publishService,
    deleteService,
    openPort,
    closePort,
    checkPort,
    remoteQueryServices,
    remotePublishService,
    remoteDeleteService,
    remoteQueryPorts,
    remoteOpenPort,
    remoteClosePort,
    remoteQueryLog,
    leave,
  }
}

function response(status, body) {
  if (!body) return new Message({ status })
  if (typeof body === 'string') return responseCT(status, 'text/plain', body)
  return responseCT(status, 'application/json', JSON.encode(body))
}

function responseCT(status, ct, body) {
  return new Message(
    {
      status,
      headers: { 'content-type': ct }
    },
    body
  )
}
