# V50 Web Frontend Security

note: all category names, section names and file name will be most likely renamed in the future.

The category focuses on requirements which protect against attacks that are executed via a web frontend for an application. These requirements will not be relevant for machine-to-machine solutions.

## V50.1 Site Isolation Architecture

| # | Description | L1 | L2 | L3 | CWE | Issue |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **50.1.1** | [ADDED] Verify that separate applications are hosted on different hostnames so as to benefit from the protections provided by the "same origin policy" and the hostname restrictions on cookies. | ✓ | ✓ | ✓ | 668 | [#1299](https://github.com/OWASP/ASVS/issues/1299) |

## V50.2 Browser Security Mechanism Headers

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **14.4.3** | [MODIFIED] Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, CSS, JSON, and JavaScript injection vulnerabilities. | ✓ | ✓ | ✓ | 1021 |
| **14.4.4** | Verify that all responses contain a X-Content-Type-Options: nosniff header. | ✓ | ✓ | ✓ | 116 |
| **14.4.5** | [MODIFIED] Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security: max-age=31536000; includeSubdomains. | ✓ | ✓ | ✓ | 523 |
| **14.4.6** | Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header to untrusted parties. | ✓ | ✓ | ✓ | 116 |
| **14.4.7** | Verify that the content of a web application cannot be embedded in a third-party site by default and that embedding of the exact resources is only allowed where necessary by using suitable Content-Security-Policy: frame-ancestors and X-Frame-Options response headers. | ✓ | ✓ | ✓ | 1021 |
| **14.4.8** | [ADDED, SPLIT FROM 14.5.3] Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header uses a strict allow list of trusted origins. When "Access-Control-Allow-Origin: *" needs to be used, verify that the responses do not include any sensitive information. | ✓ | ✓ | ✓ | 183 |

## V50.3 Browser Origin Separation

Other possible titles:
* confused deputy
* request origin
* cors setup

When accepting request on the server side, we need to be sure it is initiated by the application itself or by trusted party.

The keywords here are browser security policies like Same Origin Policy for JavaScript and also SameSite logic for cookies.

The category should contain requirements with idea:
  * Verify that request was initiated by trusted party (CSRF, CORS misconfiguration)
  * Verify that the response is readable only for trusted parties (CORS misconfiguration)

note: tags and numbers for requirements are not changed, at the moment the goal is to verify the idea and concept of the category

| # | Description | L1 | L2 | L3 | CWE | Issue |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **4.2.2** | [MODIFIED, MERGED FROM 13.2.3] Verify that the application defends against Cross-Site Request Forgery (CSRF) attacks to protect authenticated or sensitive public functionality using the development framework's built-in anti-CSRF functionality or CSRF tokens plus additional defense in depth measures. | ✓ | ✓ | ✓ | 352 | [#1652](https://github.com/OWASP/ASVS/issues/1652) |
| **4.2.3** | [ADDED] Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | | ✓ | ✓ | 346 | [#1230](https://github.com/OWASP/ASVS/issues/1230) |
| **14.5.3** | [MODIFIED, SPLIT TO 14.4.8] Verify that the Origin header is validated against a defined list of allowed origins to match the desired Cross-Origin Resource Sharing (CORS) policy. | ✓ | ✓ | ✓ | 346 | [#1230](https://github.com/OWASP/ASVS/issues/1230) |

## V50.4 XSSI

| # | Description | L1 | L2 | L3 | CWE | Issue |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **50.3.1** | [ADDED] Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | | ✓ | ✓ | | [#903](https://github.com/OWASP/ASVS/issues/903) |
| **50.3.2** | [ADDED] Verify that sensitive information is not present in JavaScript files to avoid Cross-Site Script Inclusion (XSSI) attacks. | | ✓ | ✓ | | [#903](https://github.com/OWASP/ASVS/issues/903) |

## V50.5 Unintended Content Interpretation

| # | Description | L1 | L2 | L3 | CWE | Issue |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: |
| **12.5.2** | [GRAMMAR] Verify that direct requests to uploaded files will never be executed as HTML and JavaScript content. | ✓ | ✓ | ✓ | 434 | - |
| **1.12.2** | [MODIFIED] Verify that user-uploaded files - if required to be displayed or downloaded from the application - are served by either octet stream downloads, or from an unrelated domain, such as a cloud file storage bucket. | | ✓ | ✓ | 646 | [#1406](https://github.com/OWASP/ASVS/issues/1406) |
| **50.4.2** | [PROPOSED] Verify that if a client navigates to a resource (template, API response) which are not meant to be accessed directly, the application have defense (not serving the response, serving as an attachment or sandboxed content) to avoid rendering the response in browser or showing content and functionality out of context. | | ✓ | ✓ | | [#1009](https://github.com/OWASP/ASVS/issues/1009) |

## V50.6 External Resource Integrity

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **14.2.3** | [MODIFIED] Verify that if client-side assets, such as JavaScript libraries, CSS or web fonts, are hosted externally on a Content Delivery Network (CDN) or external provider, Subresource Integrity (SRI) is used to validate the integrity of the asset. | ✓ | ✓ | ✓ | 829 |

## V50.7 Other Browser Security Considerations

| # | Description | L1 | L2 | L3 | CWE |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **50.6.1** | [ADDED] outcome from https://github.com/OWASP/ASVS/issues/959#issuecomment-1172990290 - "_Verify that the web application warns users using an old browser that does not support HTTP security features on which the application relies._" | ✓ | ✓ | ✓ | ? |
