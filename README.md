
# mod_http2 - http/2 for Apache httpd

This repository contains `mod_http2` and `mod_proxy_http2` from Apache httpd as a standalone build. It servers as early access to features and fixes before being shipped in the next Apache release. Both modules can be considered **production ready** and stable as shipped by the Apache project.

## What is it good for?

`mod_http2` provides HTTP/2 for the [Apache httpd](https://httpd.apache.org) web server. You load the module into your server  and add to your configuration:

```
Protocols h2 http/1.1
```

and it becomes available to clients talking to your server on `https:` connections. See also the [Apache documentation of the module](https://httpd.apache.org/docs/2.4/en/mod/mod_http2.html). There is a [how to h2 in apache](https://icing.github.io/mod_h2/howto.html) document with advice on how to deploy, configure and verify your ```mod_http2``` installation.

`mod_proxy_http2` can manage *backend* connections using HTTP/2 in a reverse proxy setup. See the section about [`mod_proxy_http2`](#mod_proxy_http2) for instructions.

## Thanks

The following beautiful people have directly contributed to this project via commits over the years: 
Julian Reschke, Lubos Uhliarik, Luca Toscano, MATSUMOTO Ryosuke,
 Michael Kaufmann, Michael Köller, Mike Frysinger, Nicholas Race,
 Nicolas Noble, Petri Koistinen, Sam Hurst, Tatsuhiro Tsujikawa,
 Alessandro Bianchi, Yann Ylavic, Ruediger Pluem, Rainer Jung.
 
## Versions and Releases

`mod_http2` is an official Apache httpd module since release 2.4.17. `mod_proxy_http2` has been added in Apache in 2.4.23. The versions here at github are for more frequent releases than the Apache schedule provides for.

## Index

1. [Features](#features)
1. [HowTos](#howtos)
  * [How to Server Push](#how-to-server-push)
  * [How to Early Hint](#how-to-early-hint)
  * [How to WebSocket](#how-to-websocket)
1. [Configuration](#configuration)
1. [Installation](#install)
2. [Tests](#tests)

## Features

### Core Protocol

The module, from its start, provides a 100% compliant implementation of [RFC 7540](https://www.rfc-editor.org/rfc/rfc7540), the original HTTP/2 specification.

This specification was later obsoleted by [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) with the following notable changes:

1. The Priority scheme of RFC7540 was deprecated. The implementation in `mod_http2` is still there.
2. The http/1.1 `Upgrade` mechanism, to use HTTP/2 on `http:` (no TLS), was deprecated. `mod_http2` still supports this.
3. Validation for field names and values has been narrowed. This has been implemented in `mod_http2` and the underlying `nghttp2` library.

Server `PUSH` is implemented in the module, however [browsers have been dropping this feature](https://caniuse.com/?search=server%20push). This makes use of server push only viable in specific, vertical applications.

### Extensions

The following HTTP/2 extensions are implemented in the module:

1. Bootstrapping WebSockets, [RFC 8441](https://datatracker.ietf.org/doc/html/rfc8441) is implemented in v2.0.22. This requires an Apache httpd v2.4.58 or newer to work effectively. This extensions is also called "Extended Connect", as the underlying mechanism is used for other protocols besides WebSockets.

1. HTTP Early Hints, defined in [RFC 8297](https://httpwg.org/specs/rfc8297.html), is a way to send information about additional resources to a client *before* the answer to a request has been started. This is implemented. See [How to Early Hint](#how-to-early-hint) for details.

## HowTos

### How to Server Push

In general: don't. Server Push was a feature in the original HTTP/2 protocol intended to speed up browser page loads. In practise, this turned out to be without benefits or even lead to decreased performance in page loads. Nowadays, browser no longer enable this feature, meaning any configuration you do for Apache will not take effect.

During initial HTTP/2 session negotiation, "settings" are exchanged. If a client indicates that it does not want the PUSH feature, `mod_http2` will refrain from doing so.

A better way of letting a client know about resources of interest are the "Early Hints", described in the following section.

### How to Early Hint

Early Hints is a HTTP response with status `103`, described in [RFC 8297](https://httpwg.org/specs/rfc8297.html). These "interim" responses carry headers, but do not have a body. For 103 these headers are `Link`, pointing to additional web resources of interest. 

The benefit is that a server can send 103 before the "real" response has been computed. This enables browser to start loading these much earlier, leading to improved page load times. For example:

```
H2EarlyHints on
H2EarlyHint Link "</my.css>;rel=preload;as=style"
```
would result in HTTP/2 streams 1 and 3 like:

```
->  [1] GET / HTTP/2
<-  [1] HTTP/2 103 EaryHints
        Link: </my.css>;rel=preload;as=style
->  [3] GET /my.css HTTP/2
<-  [3] HTTP/2 200 Ok
    [3] my.css content
<-  [1] HTTP/2 200 Ok
    [1] / content
    [3] my.css content
    [1] / content    
    ...
```

The caveat here is that older clients might not be prepared for receiving such 1xx responses. Modern browser do. If this feature is safe to enable depends on your application.

### How to WebSocket

WebSockets were defined in [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html) before HTTP/2 existed. It describes a mechanism to establish such bi-directional byte stream over HTTP/1.1. Later in [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441) the procedure to do this in HTTP/2 was added. The mechanisms are different.

There are two ways to serve WebSockets in Apache httpd:

#### Reverse Proxy a WebSockets Server

For this, you will have a setup for HTTP/1.1 WebSockets like:

```
ProxyPass /ws/ http://127.0.0.1:8888/ upgrade=websocket timeout=300
```
where a WebSockets server is running on localhost port 8888. The Apache mod_proxy will open a HTTP/1.1 connection and is prepared to serve the traffic back and forth once the "upgrade" to WebSockets is successful.

If you use Apache httpd v2.4.58, you can enable HTTP/2 support here with:

```
H2WebSockets on
```
The backend WebSockets server will see no difference, regardless if the Apache client talks HTTP/1.1 or HTTP/2.

#### Custom Module inside Apache

If you have developed a custom module for handling WebSockets directly inside Apache, you need to enhance your module for HTTP/2 to work. The reason being that the internal connection (e.g. the `conn_rec`) will not have a socket for input polling. You should have a look at how the "proxy tunnel" inside `mod_proxy` works.

In short: even on a update-to-date httpd, enabling `H2WebSockets on` will not be enough in this case.

## Configuration

The following configuration directives are available:

  * [H2CopyFiles](#h2copyfiles)
  * [H2Direct](#h2direct)
  * [H2EarlyHint](#h2earlyhint)
  * [H2EarlyHints](#h2earlyhints)
  * [H2MaxDataFrameLen](#h2maxdataframelen)
  * [H2MaxSessionStreams](#h2maxsessionstreams)
  * [H2MaxWorkerIdleSeconds](#h2maxworkeridleseconds)
  * [H2MaxWorkers](#h2maxworkers)
  * [H2MinWorkers](#h2minworkers)
  * [H2ModernTLSOnly](#h2moderntlsonly)
  * [H2OutputBuffering](#h2outputbuffering)
  * [H2Padding](#h2padding)
  * [H2ProxyRequests](#h2proxyrequests)
  * [H2Push](#h2push)
  * [H2PushDiarySize](#h2pushdiarysize)
  * [H2PushPriority](#h2pushpriority)
  * [H2PushResource](#h2pushresource)
  * [H2SerializeHeaders](#h2serializeheaders)
  * [H2StreamMaxMemSize](#h2streammaxmemsize)
  * [H2StreamTimeout](#h2streamtimeout)
  * [H2TLSCoolDownSecs](#h2tlscooldownsecs)
  * [H2TLSWarmUpSize](#h2tlswarmupsize)
  * [H2Upgrade](#h2upgrade)
  * [H2WebSockets](#h2websockets)
  * [H2WindowSize](#h2windowsize)


### H2CopyFiles

```
Syntax:	 H2CopyFiles on|off
Default: H2CopyFiles off
Context: server config, virtual host, directory, .htaccess
```

This directive influences how file content is handled in responses. When off, which is the default, file handles are passed from the request processing down to the main connection, using the usual Apache setaside handling for managing the lifetime of the file.

When set to on, file content is copied while the request is still being processed and the buffered data is passed on to the main connection. This is better if a third party module is injecting files with different lifetimes into the response.

An example for such a module is mod_wsgi that may place Python file handles into the response. Those files get close down when Python thinks processing has finished. That may be well before mod_http2 is done with them.

### H2Direct

```
Syntax:  H2Direct on|off
Default: H2Direct on for h2c, off for h2 protocol
Context: server config, virtual host
```
This directive toggles the usage of the HTTP/2 Direct Mode. This should be used inside a `<VirtualHost>` section to enable direct HTTP/2 communication for that virtual host.

Direct communication means that if the first bytes received by the server on a connection match the HTTP/2 preamble, the HTTP/2 protocol is switched to immediately without further negotiation. This mode is defined in RFC 7540 for the cleartext (h2c) case. Its use on TLS connections not mandated by the standard.

When a server/vhost does not have h2 or h2c enabled via Protocols, the connection is never inspected for a HTTP/2 preamble. H2Direct does not matter then. This is important for connections that use protocols where an initial read might hang indefinitely, such as NNTP.

For clients that have out-of-band knowledge about a server supporting h2c, direct HTTP/2 saves the client from having to perform an HTTP/1.1 upgrade, resulting in better performance and avoiding the Upgrade restrictions on request bodies.

This makes direct h2c attractive for server to server communication as well, when the connection can be trusted or is secured by other means.


### H2EarlyHint
```
Syntax:  H2EarlyHint name value
Context: server config, virtual host, directory, .htaccess
```

Use H2EarlyHint to add a header to an EarlyHint 103 response. This cause a 103 intermediate response to be sent to the client if early hints are enabled (see H2EarlyHints directive).

Setting such headers is additive. You may add several early hint headers of the same name.

```
H2EarlyHint Link "</006/006.css>;rel=preload;as=style"
```


### H2EarlyHints

```
Syntax:  H2EarlyHints on|off
Default: H2EarlyHints off
Context: server config, virtual host
```
This setting controls if HTTP status 103 interim responses are forwarded to the client or not. By default, this is currently not the case since a range of clients still have trouble with unexpected interim responses.

When set to on, PUSH resources announced with `H2PushResource` or `H2EarlyHint` will trigger an interim 103 response before the final response.

### H2MaxDataFrameLen
```
Syntax:  H2MaxDataFrameLen n
Default: H2MaxDataFrameLen 0
Context: server config, virtual host
```
H2MaxDataFrameLen limits the maximum amount of response body bytes placed into a single HTTP/2 DATA frame. Setting this to 0 places no limit (but the max size allowed by the protocol is observed).

The module, by default, tries to use the maximum size possible, which is somewhat around 16KB. This sets the maximum. When less response data is available, smaller frames will be sent.

### H2MaxSessionStreams

```
Syntax:  H2MaxSessionStreams n
Default: H2MaxSessionStreams 100
Context: server config, virtual host
```
This directive sets the maximum number of active streams per HTTP/2 session (e.g. connection) that the server allows. A stream is active if it is not idle or closed according to RFC 7540.

### H2MaxWorkerIdleSeconds
```
Syntax:  H2MaxWorkerIdleSeconds n
Default: H2MaxWorkerIdleSeconds 600
Context: server config
```
This directive sets the maximum number of seconds a h2 worker may idle until it shuts itself down. This only happens while the number of h2 workers exceeds H2MinWorkers.

### H2MaxWorkers
```
Syntax:  H2MaxWorkers n
Context: server config
```
This directive sets the maximum number of worker threads to spawn per child process for HTTP/2 processing. If this directive is not used, mod_http2 will chose a value suitable for the mpm module loaded.


### H2MinWorkers
```
Syntax:  H2MinWorkers n
Context: server config
```
This directive sets the minimum number of worker threads to spawn per child process for HTTP/2 processing. If this directive is not used, mod_http2 will chose a value suitable for the mpm module loaded.


### H2ModernTLSOnly
```
Syntax:  H2ModernTLSOnly on|off
Default: H2ModernTLSOnly on
Context: server config, virtual host
```
This directive toggles the security checks on HTTP/2 connections in TLS mode (https:). This can be used server wide or for specific `<VirtualHost>`s.

The security checks require that the TSL protocol is at least TLSv1.2 and that none of the ciphers listed in RFC 7540, Appendix A is used. These checks will be extended once new security requirements come into place.

The name stems from the Security/Server Side TLS definitions at mozilla where "modern compatibility" is defined. Mozilla Firefox and other browsers require modern compatibility for HTTP/2 connections. As everything in OpSec, this is a moving target and can be expected to evolve in the future.

One purpose of having these checks in mod_http2 is to enforce this security level for all connections, not only those from browsers. The other purpose is to prevent the negotiation of HTTP/2 as a protocol should the requirements not be met.

Ultimately, the security of the TLS connection is determined by the server configuration directives for mod_ssl.


### H2OutputBuffering
```
Syntax:  H2OutputBuffering on|off
Default: H2OutputBuffering on
Context: server config, virtual host
```
The directive H2OutputBuffering controls the buffering of stream output. The default is on, which is the behaviour of previous versions. When off, all bytes are made available immediately to the main connection for sending them out to the client. This fixes interop issues with certain flavours of gRPC.

### H2Padding
```
Syntax:  H2Padding numbits
Default: H2Padding 0
Context: server config, virtual host
```
With the default 0, no padding bytes are added to any payload frames, e.g. HEADERS, DATA and PUSH_PROMISE. This is the behaviour of previous versions. It means that under certain conditions, an observer of network traffic can see the length of those frames in the TLS stream.

When configuring numbits of 1-8, a random number in range [0, 2^numbits[ are added to each frame. The random value is chosen independently for each frame that the module sends back to the client.

While more padding bytes give better message length obfuscation, they are also additional traffic. The optimal number therefore depends on the kind of web traffic the server carries.

The default of 0, e.g. no padding, was chosen for maximum backward compatibility. There might be deployments where padding bytes are unwanted or do harm. The most likely cause would be a client that has a faults implementation.


### H2ProxyRequests
```
Syntax:  H2ProxyRequests on|off
Default: H2ProxyRequests off
Context: server config, virtual host
```

Similar to the [`ProxyRequests`](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxyrequests) directive. Enable this if you want HTTP/2 requests to work in a Forward Proxy setup of Apache. You should only enable this when you also have `ProxyRequests` enabled.

### H2Push
```
Syntax:  H2Push on|off
Default: H2Push on
Context: server config, virtual host, directory, .htaccess
```
This directive toggles the usage of the HTTP/2 server push protocol feature.

The HTTP/2 protocol allows the server to push other resources to a client when it asked for a particular one. This is helpful if those resources are connected in some way and the client can be expected to ask for it anyway. The pushing then saves the time it takes the client to ask for the resources itself. On the other hand, pushing resources the client never needs or already has is a waste of bandwidth.

Server pushes are detected by inspecting the Link headers of responses (see https://tools.ietf.org/html/rfc5988 for the specification). When a link thus specified has the rel=preload attribute, it is treated as a resource to be pushed.

Link headers in responses are either set by the application or can be configured via H2PushResource or using mod_headers as:

```
<Location /index.html>
    Header add Link "</css/site.css>;rel=preload"
    Header add Link "</images/logo.jpg>;rel=preload"
</Location>
```

As the example shows, there can be several link headers added to a response, resulting in several pushes being triggered. There are no checks in the module to avoid pushing the same resource twice or more to one client. Use with care.

HTTP/2 server pushes are enabled by default. On a server or virtual host, you may enable/disable this feature for any connection to the host. In addition, you may disable PUSH for a set of resources in a Directory/Location. This controls which resources may cause a PUSH, not which resources may be sent via PUSH.

```
H2Push off
```

Last but not least, pushes happen only when the client signals its willingness to accept those. Most browsers do not. Also, pushes also only happen for resources from the same authority as the original response is for.

### H2PushDiarySize

```
Syntax:  H2PushDiarySize n
Default: H2PushDiarySize 256
Context: server config, virtual host
```

This directive toggles the maximum number of HTTP/2 server pushes that are remembered per HTTP/2 connection. This can be used inside the `<VirtualHost>` section to influence the number for all connections to that virtual host.

The push diary records a digest of pushed resources (their URL) to avoid duplicate pushes on the same connection. These value are not persisted, so clients opening a new connection will experience known pushes again.

If the maximum size is reached, newer entries replace the oldest ones. A diary entry uses 8 bytes, letting a default diary with 256 entries consume around 2 KB of memory.

A size of 0 will effectively disable the push diary.

### H2PushPriority

```
Syntax:  H2PushPriority mime-type [after|before|interleaved] [weight]
Default: H2PushPriority * After 16
Context: server config, virtual host
```

This directive defines the priority handling of pushed responses based on the content-type of the response. This is usually defined per server config, but may also appear in a virtual host.

HTTP/2 server pushes are always related to a client request. Each such request/response pairs, or streams have a dependency and a weight, together defining the priority of a stream.

When a stream depends on another, say X depends on Y, then Y gets all bandwidth before X gets any. Note that this does not mean that Y will block X. If Y has no data to send, all bandwidth allocated to Y can be used by X.

When a stream has more than one dependent, say X1 and X2 both depend on Y, the weight determines the bandwidth allocation. If X1 and X2 have the same weight, they both get half of the available bandwidth. If the weight of X1 is twice as large as that for X2, X1 gets twice the bandwidth of X2.

Ultimately, every stream depends on the root stream which gets all the bandwidth available, but never sends anything. So all its bandwidth is distributed by weight among its children. Which either have data to send or distribute the bandwidth to their own children. And so on. If none of the children have data to send, that bandwidth get distributed somewhere else according to the same rules.

The purpose of this priority system is to always make use of available bandwidth while allowing precedence and weight to be given to specific streams. Since, normally, all streams are initiated by the client, it is also the one that sets these priorities.

Only when such a stream results in a PUSH, gets the server to decide what the initial priority of such a pushed stream is. In the examples below, X is the client stream. It depends on Y and the server decides to PUSH streams P1 and P2 onto X.

#### Default Priority Rule

```
H2PushPriority * After 16
```

which reads as 'Send a pushed stream of any content-type depending on the client stream with weight 16'. And so P1 and P2 will be send after X and, as they have equal weight, share bandwidth equally among themselves.

#### Interleaved Priority Rule

```
H2PushPriority text/css Interleaved 256
```

which reads as 'Send any CSS resource on the same dependency and weight as the client stream'. If P1 has content-type 'text/css', it will depend on Y (as does X) and its effective weight will be calculated as P1ew = Xw * (P1w / 256). With P1w being 256, this will make the effective weight the same as the weight of X. If both X and P1 have data to send, bandwidth will be allocated to both equally.

With Pw specified as 512, a pushed, interleaved stream would get double the weight of X. With 128 only half as much. Note that effective weights are always capped at 256.

#### Before Priority Rule
```
H2PushPriority application/json Before
```

This says that any pushed stream of content type 'application/json' should be send out before X. This makes P1 dependent on Y and X dependent on P1. So, X will be stalled as long as P1 has data to send. The effective weight is inherited from the client stream. Specifying a weight is not allowed.

Be aware that the effect of priority specifications is limited by the available server resources. If a server does not have workers available for pushed streams, the data for the stream may only ever arrive when other streams have been finished.

Last, but not least, there are some specifics of the syntax to be used in this directive:

`*` is the only special content-type that matches all others. `image/*` will not work.
The default dependency is `After`.
There are also default weights: for `After` it is 16, `interleaved` is 256.

### Shorter Priority Rules
```
H2PushPriority application/json 32         # an After rule
H2PushPriority image/jpeg before           # weight inherited
H2PushPriority text/css   interleaved      # weight 256 default
```

### H2PushResource

```
Syntax:  H2PushResource [add] path [critical]
Context: server config, virtual host, directory, .htaccess
```
When added to a directory/location HTTP/2 PUSHes will be attempted for all paths added via this directive. This directive can be used several times for the same location.

This directive pushes resources much earlier than adding Link headers via mod_headers. mod_http2 announces these resources in a 103 Early Hints interim response to the client. That means that clients not supporting PUSH will still get early preload hints.

In contrast to setting Link response headers via mod_headers, this directive will only take effect on HTTP/2 connections.

By adding critical to such a resource, the server will give processing it more preference and send its data, once available, before the data from the main request.


### H2SerializeHeaders
```
Syntax:  H2SerializeHeaders on|off
Default: H2SerializeHeaders off
Context: server config, virtual host
```
This directive toggles if HTTP/2 requests shall be serialised in HTTP/1.1 format for processing by httpd core or if received binary data shall be passed into the request_recs directly.

Serialisation will lower performance, but gives more backward compatibility in case custom filters/hooks need it.

### H2StreamMaxMemSize
```
Syntax:  H2StreamMaxMemSize bytes
Default: H2StreamMaxMemSize 65536
Context: server config, virtual host
```
This directive sets the maximum number of outgoing data bytes buffered in memory for an active streams. This memory is not allocated per stream as such. Allocations are counted against this limit when they are about to be done. Stream processing freezes when the limit has been reached and will only continue when buffered data has been sent out to the client.

### H2StreamTimeout
```
Syntax:  H2StreamTimeout time-interval[s]
Default: Value of "Timeout" directive
Context: server config, virtual host, directory
```
H2StreamTimeout specifies the maximum time that a stream being processed will wait for its data to be sent/received.

### H2TLSCoolDownSecs
```
Syntax:  H2TLSCoolDownSecs seconds
Default: H2TLSCoolDownSecs 1
Context: server config, virtual host
```
This directive sets the number of seconds of idle time on a TLS connection before the TLS write size falls back to small (~1300 bytes) length. This can be used server wide or for specific `<VirtualHost>`s.

See H2TLSWarmUpSize for a description of TLS warmup. H2TLSCoolDownSecs reflects the fact that connections may deteriorate over time (and TCP flow adjusts) for idle connections as well. It is beneficial to overall performance to fall back to the pre-warmup phase after a number of seconds that no data has been sent.

In deployments where connections can be considered reliable, this timer can be disabled by setting it to 0.

The following example sets the seconds to zero, effectively disabling any cool down. Warmed up TLS connections stay on maximum record size.

```
H2TLSCoolDownSecs 0
```

### H2TLSWarmUpSize
```
Syntax:  H2TLSWarmUpSize amount
Default: H2TLSWarmUpSize 1048576
Context: server config, virtual host
```
This directive sets the number of bytes to be sent in small TLS records (~1300 bytes) until doing maximum sized writes (16k) on https: HTTP/2 connections. This can be used server wide or for specific `<VirtualHost>`s.

Measurements by google performance labs show that best performance on TLS connections is reached, if initial record sizes stay below the MTU level, to allow a complete record to fit into an IP packet.

While TCP adjust its flow-control and window sizes, longer TLS records can get stuck in queues or get lost and need retransmission. This is of course true for all packets. TLS however needs the whole record in order to decrypt it. Any missing bytes at the end will stall usage of the received ones.

After a sufficient number of bytes have been send successfully, the TCP state of the connection is stable and maximum TLS record sizes (16 KB) can be used for optimal performance.

In deployments where servers are reached locally or over reliable connections only, the value might be decreased with 0 disabling any warmup phase altogether.

The following example sets the size to zero, effectively disabling any warmup phase.

```
H2TLSWarmUpSize 0
```

### H2Upgrade

```
Syntax:  H2Upgrade on|off
Default: H2Upgrade on for h2c, off for h2 protocol
Context: server config, virtual host, directory, .htaccess
```
This directive toggles the usage of the HTTP/1.1 Upgrade method for switching to HTTP/2. This should be used inside a `<VirtualHost>` section to enable Upgrades to HTTP/2 for that virtual host.

This method of switching protocols is defined in HTTP/1.1 and uses the "Upgrade" header (thus the name) to announce willingness to use another protocol. This may happen on any request of a HTTP/1.1 connection.

This method of protocol switching is enabled by default on cleartext (potential h2c) connections and disabled on TLS (potential h2), as mandated by RFC 7540.

Please be aware that Upgrades are only accepted for requests that carry no body. POSTs and PUTs with content will never trigger an upgrade to HTTP/2. See H2Direct for an alternative to Upgrade.

This mode only has an effect when h2 or h2c is enabled via the Protocols.


### H2WebSockets
```
Syntax:  H2WebSockets on|off
Default: H2WebSockets off
Context: server config, virtual host
```

Enable support for bootstrapping WebSockets over HTTP/2. This, in general, requires Apache httpd 2.4.58 or newer. See [How to WebSocket](#how-to-websocket) for details.

### H2WindowSize
```
Syntax:  H2WindowSize bytes
Default: H2WindowSize 65535
Context: server config, virtual host
```
This directive sets the size of the window that is used for flow control from client to server and limits the amount of data the server has to buffer. The client will stop sending on a stream once the limit has been reached until the server announces more available space (as it has processed some of the data).

This limit affects only request bodies, not its meta data such as headers. Also, it has no effect on response bodies as the window size for those are managed by the clients.


## Install

You need a built Apache httpd 2.4.48 or newer, including apxs and headers to compile and 
run this module. Additionally, you need an installed libnghttp2, at least in version
1.7.0. And additionally, you want an installed OpenSSL 1.0.2 or later.

tl;dr

**You need an installed recent Apache 2.4.x**

### Build from git

```
> autoreconf -i
> automake
> autoconf
> ./configure --with-apxs=<path to apxs>
> make
```


### Apache 2.4.x Packages

* **Ubuntu**: [ppa by ondrej](https://launchpad.net/~ondrej/+archive/ubuntu/apache2) for Ubuntu 14.04 and others
* **Fedora**: [shipped in Fedora 23 and later](https://bodhi.fedoraproject.org/updates/?packages=httpd)
* **Debian** sid (unstable) [how to install debian sid](https://wiki.debian.org/InstallFAQ#Q._How_do_I_install_.22unstable.22_.28.22sid.22.29.3F)
* **Gentoo**: [latest stable](https://packages.gentoo.org/packages/www-servers/apache)
* **FreeBSD**: [Apache 2.4 port includes mod_http2](http://www.freshports.org/www/apache24/) / [mod_http2 port](http://www.freshports.org/www/mod_http2/)

## Tests

I decided to make the test suite part of this repository again. The existing suite resides
in test Apache httpd test repository and is a set of shell scripts. It works, but I miss
features that professional test frameworks bring. The tests included here use ```python3``` and ```pytest``` which I think is an excellent way to do tests. I use it also in my Let's Encrypt module ```mod_md```. 

You can build the module without having the test prerequisites. If you want to run them, however, you need ```pytest```, ```python3``` and a ```curl``` with http2 support. Then you can

```
> make
> make test
```


## `mod_proxy_http2`

This module is part of the Apache httpd proxy architecture and functions similar to `mod_proxy_http` 
and friends. To configure it, you need to use ```h2:``` or ```h2c:``` in the proxy URL. Example:

```
<Proxy "balancer://h2-local">
    BalancerMember "h2://test.example.org:SUBST_PORT_HTTPS_SUBST"
</Proxy>
<Proxy "balancer://h2c-local">
    BalancerMember "h2c://test.example.org:SUBST_PORT_HTTP_SUBST"
</Proxy>

<IfModule proxy_http2_module>
    ProxyPass "/h2proxy" "balancer://h2-local"
    ProxyPassReverse "/h2proxy" "balancer://h2-local"
    ProxyPass "/h2cproxy" "balancer://h2c-local"
    ProxyPassReverse "/h2cproxy" "balancer://h2c-local"
</IfModule>
```

This will only work under the following conditions:
* the backend speaks HTTP/2, the module will not fallback to HTTP/1.1
* the backend supports HTTP/2 direct mode (see also ```H2Direct``` directive of ```mod_http2```)

All other common httpd ```proxy``` directives also apply.


## Licensing

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.  This file is offered as-is,
without warranty of any kind. See LICENSE for details.



