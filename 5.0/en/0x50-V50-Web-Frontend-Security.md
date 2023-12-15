# V50 Web Frontend Security

The category focuses on requirements which protect against attacks that are executed via a web frontend for an application. These requirements will not be relevant for machine-to-machine solutions.


## V50.1 Site Isolation Architecture

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **50.1.1** | [ADDED] Verify that separate applications are hosted on different hostnames to benefit from the restrictions provided by the "same-origin policy" including how documents or scripts loaded by one origin can interact with resources from another origin and hostname restrictions on cookies. | ✓ | ✓ | ✓ | 668 |


## V50.2 Browser Security Mechanism Headers

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **50.2.1** | [MODIFIED, MOVED FROM 14.4.3] Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, CSS, JSON, and JavaScript injection vulnerabilities. | ✓ | ✓ | ✓ | 1021 |
| **50.2.2** | [MOVED FROM 14.4.4] Verify that all responses contain a X-Content-Type-Options: nosniff header. | ✓ | ✓ | ✓ | 116 |
| **50.2.3** | [MODIFIED, MOVED FROM 14.4.5] Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=31536000; includeSubdomains. | ✓ | ✓ | ✓ | 523 |
| **50.2.4** | [MOVED FROM 14.4.6] Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to untrusted parties. | ✓ | ✓ | ✓ | 116 |
| **50.2.5** | [MOVED FROM 14.4.7] Verify that the content of a web application cannot be embedded in a third-party site by default and that embedding of the exact resources is only allowed where necessary by using suitable Content-Security-Policy: frame-ancestors and X-Frame-Options response headers. | ✓ | ✓ | ✓ | 1021 |
| **50.2.6** | [ADDED, SPLIT FROM 14.5.3] Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header uses a strict allow list of trusted origins. When "Access-Control-Allow-Origin: *" needs to be used, verify that the responses do not include any sensitive information. | ✓ | ✓ | ✓ | 183 |


## V50.3 Browser Origin Separation

When accepting a request on the server side, we need to be sure it is initiated by the application itself or by a trusted party.

The keywords here are browser security policies like Same Origin Policy for JavaScript and also SameSite logic for cookies.

The category should contain requirements with ideas:

* Verify that the request was initiated by a trusted party (CSRF, CORS misconfiguration)
* Verify that the response is readable only for trusted parties (CORS misconfiguration)

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **50.3.1** | [MODIFIED, MOVED FROM 4.2.2, MERGED FROM 13.2.3] Verify that the application defends against Cross-Site Request Forgery (CSRF) attacks to protect authenticated or sensitive public functionality using the development framework's built-in anti-CSRF functionality or CSRF tokens plus additional defense in depth measures. | ✓ | ✓ | ✓ | 352 |
| **50.3.2** | [ADDED] Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | | ✓ | ✓ | 346 |
| **50.3.3** | [ADDED, SPLIT FROM 14.5.3] Verify that the Origin header is validated against a defined list of allowed origins to match the desired Cross-Origin Resource Sharing (CORS) policy. | ✓ | ✓ | ✓ | 346 |


## V50.4 Cross-Site Script Inclusion

TBD


## V50.5 Unintended Content Interpretation

TBD


## V50.6 External Resource Integrity

TBD

## V50.7 Other Browser Security Considerations

TBD


## References

For more information, see also:

* [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
* [Exploiting CORS misconfiguration for BitCoins and Bounties](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [Sandboxing third party components](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html#sandboxing-content)
* [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
* [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)