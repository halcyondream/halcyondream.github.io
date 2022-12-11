# Daily NIST NVD Parser

Today, I wrote a very simple NVD parser, written entirely in Javascript. Its purpose is to provide a brief overview of vulnerabilities that were identified between the previous day and the time you load the page. Everything runs entirely in the browser. Only information from the NVD feed is written to the DOM, and that data is sanitized through HTML-encoding, which is written into the global `String` prototype.

You can [try the parser](https://halcyondream.github.io/nvdparser) yourself, or [read the source code](https://github.com/halcyondream/halcyondream.github.io/blob/main/nvdparser/nvdparser.js).

# Considerations

HTML-encoding occurs when any data is written from the API to the DOM. An attacker should not be able to inject unsafe characters (for example, to cause a cross-site scripting attack). 

Of course, there may exist a possibility for an attacker to exploit the use of string concatenation to create the URL. Likewise, although HTML-encoding does occur, the means by which it encodes data is pretty simple. It is possible that an implementation flaw in the encoder method could cause this encoding to fail (for example, triggering a ReDoS in the `s.match` logic). 

Finally, the `fetch` occurs in the browser itself. A user who makes too many requests to the database (for example, by refreshing the page too many times) may prevent themselves from retrieving the API data, thus causing a kind of self-DoS.

