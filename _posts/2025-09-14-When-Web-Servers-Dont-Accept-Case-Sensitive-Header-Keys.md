---
layout: post
title: When Web Servers Don't Accept Case-insensitive Header Keys
date: 2025-09-14
---

There's a fun caveat with what the HTTP specification says about headers versus the way they are implemented. 

The story starts with [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#name-core-semantics), which addresses HTTP fields in Section 5:

> HTTP uses "fields" to provide data in the form of extensible name/value pairs with a registered key namespace...
>
> A field name labels the corresponding field value as having the semantics defined by that name. For example, the [Date](https://www.rfc-editor.org/rfc/rfc9110.html#field.date) header field is defined in [Section 6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#field.date) as containing the origination timestamp for the message in which it appears.
>
> ```
> field-name     = token
> ```
>
> Field names are case-insensitive and ought to be registered within the "Hypertext Transfer Protocol (HTTP) Field Name Registry" ...

HTTP field names are, thus, case-insensitive. 

Headers, defined in Section 6.3, are one such example of a field:

> The "header section" of a message consists of a sequence of header field lines. Each header field might modify or extend message semantics, describe the sender, define the content, or provide additional context.

So, a web client may send headers like `Foo: Bar`, `foo: Bar`, `FoO: Bar`, and so on, and the server must accept them regardless of their case.

Framework specifications, however, don't always honor this rule. Sometimes, they offer a method, but they don't apply it by default. Other times, they leave it entirely up to the developer to decide how to implement it. 

Of course, this also leaves some wiggle room for developers *not* to implement it at all.

This isn't frustrating in itself, but many web clients will canonicalize the headers before sending them out. And *that* isn't in itself frustrating, but many security tools, like Burp Suite and Postman, will also canonicalize headers before sending them. This can introduce some pain-points during a web app or API assessment.

Suppose you have an API endpoint defined like this (in pseudocode):

```
@endpoint(method="GET", path="/userinfo")
def handler(request) is:
	if request.header["authToken"], then
		return 200, userInfo()
	else
		return 403, error()
```

In this example, the client must send a request whose `authorization` header is case-sensitive. This is a common implementation mistake with frameworks like Python, Node, and so forth.

The following request will successfully get the user's info:

```
GET /v1/userinfo HTTP/2
Host: api.server.tld
authToken: my.foo.jwt
...

HTTP/2 200 OK
...
```

Unfortunately, because many web clients will canonicalize the header key, they will instead send this, which will fail:

```
GET /v1/userinfo HTTP/2
Host: api.server.tld
Authtoken: my.foo.jwt
...

HTTP/2 403 Forbidden
```

A simple fix here is to recommend the use of an appropriate header, such as the `Authorization` header, which exists to help with this exact case. However, the root cause is that the application has no consistent way to handle the different header cases, which it is required to do per the HTTP specification. The developer is left to normalize these values in order for the application to remain in compliance.

In Python, you can trivially normalize headers from a `dict`:

```python
normalize = lambda s: s.lower()

headers = lambda d: dict((normalize(lower), v) for k,v in d.items())

event["headers"] = headers(event["headers"])

validate_jwt(event["headers"]["authorizationtoken"])
...
```

Here, the application can use only the lowercase representation of the headers. This provides a consistent means to get their values. The developer can take it a step further by refactoring `normalize` to convert the key strings into their canonical MIME forms: for example, transforming `x-api-key` to `X-Api-Key`, and designing the application to use this form instead.

There may be lots of corner cases involving custom headers where this problem rears its head. It's important to be aware of the behavior, why it's problematic, and what to do about it. It's especially annoying when you encounter these issues in web clients and web testing tools or frameworks.

Nuclei is a great tool and lets you set custom, case-sensitive headers for all but one case: secrets from authenticated scans that are used as headers. Consider the following authenticated scan configuration:

```
$ cat config.yaml

env-vars: true 
templates:
  - "/templates/test.yaml"
exclude-tags:
  - noscan
secret-file:
  - "/templates/secret.yaml"
disable-update-check: true 
json: true 
target:
  - "https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7"
store-responses: true 
prefetch-secrets: true

$ cat secret.yaml

id: auth-tokens 
info:
  name: Get and set an authorization token 
  author: me
  severity: info 
  tags: noscan 
dynamic:
  - template: /templates/auth.yaml
    input: "https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7"
    variables:
      - key: x
        value: y
    domains:
      - "webhook.site"
    type: header
    headers:
      - key: bAr
        value: "{{barAuthToken}}"

$ cat auth.yaml

id: auth 
info:
  name: Actually get the auth token from the API 
  author: me
  severity: info 
  tags: noscan 
requests:
  - method: POST
    path:
      - "{{BaseURL}}/check"
    headers:
      Content-Type: application/json
      Accept: application/json 
    body: |
      {"hello": "world"}
    matchers-condition: and 
    matchers:
      - type: dsl 
        dsl:
          - "status_code == 200"
    extractors:
      - type: json 
        part: body 
        name: barAuthToken
        json: [".bar"]$ 
```

The config template specifies which secrets file(s) should be used. The secrets file will run its own template, `auth.yaml`, which performs the request and pops the authorization tokens from the response. So long as this succeeds, the `test.yaml` file from the config will run with that header.

```
$ podman run --rm \
	-v $(pwd):/templates \
	--env-file ".env" \
	docker.io/projectdiscovery/nuclei:v3.4.4 \
	-config /templates/config.yaml \
	-vv -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.4

                projectdiscovery.io

...

POST /4ad356ac-e855-4032-8210-903aee8a58f7/check HTTP/1.1
Host: webhook.site
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.3
Connection: close
Content-Length: 20
Accept: application/json
Accept-Language: en
Content-Type: application/json
Accept-Encoding: gzip

{"hello": "world"}
[DBG] [auth] Dumped HTTP response https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/check

HTTP/1.1 200 OK
Connection: close
Transfer-Encoding: chunked
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Length,Content-Range
Cache-Control: no-cache, private
Content-Type: application/json
Date: Sat, 13 Sep 2025 16:42:02 GMT
Server: nginx
X-Request-Id: 8f6011f0-bb9a-4d12-ba3e-85eb40d7958f
X-Token-Id: 4ad356ac-e855-4032-8210-903aee8a58f7

{"bar": "SomeBarValue"}
[auth:dsl-1] [http] [info] https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/check ["SomeBarValue"]
```

This simulates how an API will provide an authorization token, and how Nucleus can use that response to authorize successive requests in the runner. The indication of success is the last line in this output.

Unfortunately, the authenticated scan method will convert only the secret headers to their canonical forms. Notice that the header `bAr` from the secrets file is automatically converted:

```
[test] Test the case sensitivity of the header keys (@me) [low]
[INF] [test] Dumped HTTP request for https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/test

POST /4ad356ac-e855-4032-8210-903aee8a58f7/test HTTP/1.1
Host: webhook.site
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Connection: close
Content-Length: 22
Accept: application/json
Accept-Language: en
Bar: SomeBarValue
Content-Type: application/json
Accept-Encoding: gzip
```

This is problematic for testing a non-compliant API server.

At the time of writing, this corner case accepts headers like such:

```go
// Apply applies the headers auth strategy to the request
func (s *HeadersAuthStrategy) Apply(req *http.Request) {
	for _, header := range s.Data.Headers {
		req.Header.Set(header.Key, header.Value)
	}
}

// ApplyOnRR applies the headers auth strategy to the retryable request
func (s *HeadersAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	for _, header := range s.Data.Headers {
		req.Header.Set(header.Key, header.Value)
	}
}

```

The `Header.Set` method actually resolves deep into the `net/http` package, which explicitly sets a canonical key for each header:

```go
// Set sets the header entries associated with key to the
// single element value. It replaces any existing values
// associated with key. The key is case insensitive; it is
// canonicalized by [textproto.CanonicalMIMEHeaderKey].
// To use non-canonical keys, assign to the map directly.
func (h Header) Set(key, value string) {
	textproto.MIMEHeader(h).Set(key, value)
}
```

The `textproto` package handles the setting of these canonical values:

```go
// Set sets the header entries associated with key to
// the single element value. It replaces any existing
// values associated with key.
func (h MIMEHeader) Set(key, value string) {
	h[CanonicalMIMEHeaderKey(key)] = []string{value}
}
...

// CanonicalMIMEHeaderKey returns the canonical format of the
// MIME header key s. The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase. For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// MIME header keys are assumed to be ASCII only.
// If s contains a space or invalid header field bytes, it is
// returned without modifications.
func CanonicalMIMEHeaderKey(s string) string {
	// Quick check for canonical encoding.
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !validHeaderFieldByte(c) {
			return s
		}
		if upper && 'a' <= c && c <= 'z' {
			s, _ = canonicalMIMEHeaderKey([]byte(s))
			return s
		}
		if !upper && 'A' <= c && c <= 'Z' {
			s, _ = canonicalMIMEHeaderKey([]byte(s))
			return s
		}
		upper = c == '-'
	}
	return s
}

// validHeaderFieldByte reports whether c is a valid byte in a header
// field name. RFC 7230 says:
//
//	header-field   = field-name ":" OWS field-value OWS
//	field-name     = token
//	tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//	        "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
//	token = 1*tchar
func validHeaderFieldByte(c byte) bool {
	// mask is a 128-bit bitmap with 1s for allowed bytes,
	// so that the byte c can be tested with a shift and an and.
	// If c >= 128, then 1<<c and 1<<(c-64) will both be zero,
	// and this function will return false.
	const mask = 0 |
		(1<<(10)-1)<<'0' |
		(1<<(26)-1)<<'a' |
		(1<<(26)-1)<<'A' |
		1<<'!' |
		1<<'#' |
		1<<'$' |
		1<<'%' |
		1<<'&' |
		1<<'\'' |
		1<<'*' |
		1<<'+' |
		1<<'-' |
		1<<'.' |
		1<<'^' |
		1<<'_' |
		1<<'`' |
		1<<'|' |
		1<<'~'
	return ((uint64(1)<<c)&(mask&(1<<64-1)) |
		(uint64(1)<<(c-64))&(mask>>64)) != 0
}
```

The `CanonicalMIMEHeaderKey` is of interest for two reasons. On one hand, it's responsible for converting the case to a consistent format (i.e., `content-type` to `Content-Type`). On the other hand, if invalid bytes are detected, it just sends back the header:

```go
// If s contains a space or invalid header field bytes, it is
// returned without modifications.
func CanonicalMIMEHeaderKey(s string) string {
	...
		if !validHeaderFieldByte(c) {
			return s
		}
  ...
	return s
}
```

So, if you remove its uppper-lower-transformation logic, you're left with a pretty useless function. In this case, that's not the worst thing that will happen. Nuclei should ideally handle the header's validity when it validates the YAML.

This also means that a vulnerability with the YAML parsing could lead to invalid header bytes. This is one reason why you should carefully vet any inputs before implicitly trusting them, and is likely implied in Nuclei's warnings about using unsigned templates. Exploits that try to take advantage of this should be investigated, but it's not really the scope of this discussion.

With all of that in mind, you can make a quick fix to `pkg/authprovider/authx/headers_auth.go` and set case-sensitive keys that still conform with MIME standards:

```go
// Apply applies the headers auth strategy to the request
func (s *HeadersAuthStrategy) Apply(req *http.Request) {
	for _, header := range s.Data.Headers {
		req.Header[header.Key] = []string{header.Value}
	}
}

// ApplyOnRR applies the headers auth strategy to the retryable request
func (s *HeadersAuthStrategy) ApplyOnRR(req *retryablehttp.Request) {
	for _, header := range s.Data.Headers {
		req.Header[header.Key] = []string{header.Value}
	}
}
```

Then build it:

```
docker build -t nuclei:noncanon
```

There's an open bug in Nuclei that prevents dynamic secret scans from prefetching, so you'll need to target an old version as of now. (There's a PR for this so hopefully not forever.) At the time of writing, Nuclei 3.4.4 is successfully able to run this and is the version pushed in the latest container, so make sure to:

```
git checkout v3.4.4
```

Then make the previous changes, build the container, etc:

```
$ podman build -t nuclei:3.4.4-nocanon .
...

$ podman run --rm \
	-v $(pwd):/templates \
	--env-file ".env" \
	nuclei:3.4.4-nocanon \
	-config /templates/config.yaml \
	-vv -debug

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.4

                projectdiscovery.io

...
[INF] [auth] Dumped HTTP request for https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/check

POST /4ad356ac-e855-4032-8210-903aee8a58f7/check HTTP/1.1
Host: webhook.site
User-Agent: Mozilla/5.0 (Kubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0
Connection: close
Content-Length: 20
Accept: application/json
Accept-Language: en
Content-Type: application/json
Accept-Encoding: gzip

{"hello": "world"}
[DBG] [auth] Dumped HTTP response https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/check

HTTP/1.1 200 OK
Connection: close
Transfer-Encoding: chunked
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Length,Content-Range
Cache-Control: no-cache, private
Content-Type: application/json
Date: Sat, 13 Sep 2025 13:18:57 GMT
Server: nginx
X-Request-Id: c05689d9-cedc-4591-8997-4f143f06121b
X-Token-Id: 4ad356ac-e855-4032-8210-903aee8a58f7

{"bar": "SomeBarValue"}
[auth:dsl-1] [http] [info] https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/check ["SomeBarValue"]
[test] Test the case sensitivity of the header keys (@me) [low]
[INF] [test] Dumped HTTP request for https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/test

POST /4ad356ac-e855-4032-8210-903aee8a58f7/test HTTP/1.1
Host: webhook.site
User-Agent: Mozilla/5.0 (Fedora; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0
Connection: close
Content-Length: 22
Accept: application/json
Accept-Language: en
Content-Type: application/json
bAr: SomeBarValue
Accept-Encoding: gzip

{"testing": "world"}
[DBG] [test] Dumped HTTP response https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/test

HTTP/1.1 200 OK
Connection: close
Transfer-Encoding: chunked
Access-Control-Allow-Headers: *
Access-Control-Allow-Methods: *
Access-Control-Allow-Origin: *
Access-Control-Expose-Headers: Content-Length,Content-Range
Cache-Control: no-cache, private
Content-Type: application/json
Date: Sat, 13 Sep 2025 13:18:58 GMT
Server: nginx

{"bar": "SomeBarValue"}
[test:dsl-1] [http] [low] https://webhook.site/4ad356ac-e855-4032-8210-903aee8a58f7/test
[INF] Scan completed in 428.752346ms. 2 matches found.
```

The case-sensitive `bAr: SomeBarValue` is set via the secrets file and sent in successive requests to the API.