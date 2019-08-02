Some burp plugins

*BurpXHookSignature*

First attempt at one, mostly taken from [forgenix](https://www.foregenix.com/blog/testing-problematic-authorisation-tokens-with-burp)

ran into trouble renaming `NAME = "Bearer Authorization Token"` but got it working in limited time, maybe it will become apparent with time ;-)

Basically, takes the body of the requests, concatanates it to the end of a shared secret key, hashes that value, and creates a header `X-Hook-Signature` with each request. 