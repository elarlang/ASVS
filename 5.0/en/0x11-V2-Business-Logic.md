# V2 Business Logic

## Control Objective

Ensure that a verified application satisfies the following high-level requirements:

* The business logic flow is sequential, processed in order, and cannot be bypassed.
* Business logic includes limits and controls to detect and prevent automated attacks, such as continuous small funds transfers and adding a million friends one at a time.
* High-value business logic flows have considered abuse cases and malicious actors, and have protections against spoofing, tampering, information disclosure, and elevation of privilege attacks.

## V2.1 Business Logic Documentation

Business logic documentation should clearly define business logic limits, validation rules, and contextual consistency of combined data items so that it is clear what needs to be implemented in the application.

| # | Description | Level | #v5.0.be |
| :---: | :--- | :---: | :---: |
| **2.1.1** | [ADDED, SPLIT FROM 1.5.1, LEVEL L2 > L1] Verify that input validation rules are documented and define how to ensure the logical and contextual consistency of combined data items, such as checking that suburb and zip code match. | 1 | v5.0.be-1.11.6 |
| **2.1.2** | [ADDED, SPLIT FROM 1.5.1, LEVEL L2 > L1] Verify that input validation rules define how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, e-mail addresses, telephone numbers, or it could be an internal data format. | 1 | v5.0.be-1.11.5 |
| **2.1.3** | [ADDED] Verify that expectations for business logic limits and validations are documented including both per-user and also globally across the application. | 2 | v5.0.be-1.11.4 |

## V2.2 Input Validation

Properly implemented input validation controls, using positive allowlists and strong data typing, provide an important enforcement of business logic controls or functional expectations around the type of data that the app expects to receive.

In this context, "input" could come from a wide variety of sources including HTML form fields, REST requests, URL parameters, HTTP header fields, cookies, files on disk, databases and external APIs.

Business logic controls could be that a particular input should be a number which is less than 100. Functional expectations might be that a certain number should be below a certain threshold as the number governs how many times a particular loop should take place and a high number could lead to excessive processing and a potential denial of service condition.

Whilst we no longer explicitly mandate schema validation, this may be the most effective mechanism for full validation coverage of HTTP APIs or other interfaces which use JSON or XML. Please note the following on Schema Validation:

* As at this time, there is a "published version" of the JSON schema validation specification, which is considered production ready. However, there is not yet a version which is considered strictly "stable". As such, when considering using JSON schema validation, be sure there are no gaps with the guidance in the requirements below.
* Due to the lack of a formal stable version of the JSON schema validation specification, carefully monitor any JSON schema validation libraries in use, as they may need to be updated once the standard is formalized and bugs are ironed out of reference implementations.
* Due to issues with XXE attacks against DTDs, DTD validation should not be used, and framework DTD evaluation should be disabled.

Input validation provides valuable hygiene for the application in making sure that data is received in the correct format and should be applied to all inputs where possible. However, it does not remove or replace the need to use correct encoding, parameterization or sanitization when using the data in another component or for presenting it for output.

| # | Description | Level | #v5.0.be |
| :---: | :--- | :---: | :---: |
| **2.2.1** | [MODIFIED, MOVED FROM 5.1.3, SPLIT FROM 5.1.4, MERGED FROM 11.1.5, COVERS 13.2.2, 13.3.1] Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allowed list of values, patterns or ranges or alternatively be based on comparing to an expected structure or logical limit, according to pre-defined rules. For L1 this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | 1 | v5.0.be-11.3.1 |
| **2.2.2** | [MODIFIED, MOVED FROM 1.5.3, LEVEL L2 > L1] Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability, it must not be relied upon as a security control. | 1 | v5.0.be-11.3.2 |
| **2.2.3** | [ADDED, SPLIT FROM 5.1.4, LEVEL L1 > L2] Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | 2 | v5.0.be-11.3.3 |

## V2.3 Business Logic Security

This section considers key requirements to ensure that the application enforces business logic processes in the correct way and is not vulnerable to attacks that exploit the logic and flow of the application.

| # | Description | Level | #v5.0.be |
| :---: | :--- | :---: | :---: |
| **2.3.1** | Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps. | 1 | v5.0.be-11.1.1 |
| **2.3.2** | [MODIFIED] Verify that business logic limits are implemented as per the application's documentation, to avoid business logic flaws being exploited. | 2 | v5.0.be-11.1.3 |
| **2.3.3** | [ADDED] Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety, or it is rolled back to the previous correct state. | 2 | v5.0.be-11.1.9 |
| **2.3.4** | [ADDED] Verify that high-value business logic flows are restricted with multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to critical nuclear facility operations, healthcare record modifications, access to classified information, or safety overrides in manufacturing. | 3 | v5.0.be-11.1.10 |

## V2.4 Anti-automation

This section includes anti-automation controls to ensure that human-like interactions are required and excessive automated requests are prevented.

| # | Description | Level | #v5.0.be |
| :---: | :--- | :---: | :---: |
| **2.4.1** | [MODIFIED, MOVED FROM 11.1.4, LEVEL L1 > L2] Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage data creation, quota exhaustion, rate limit breaches, denial of service, or overuse of costly resources. | 2 | v5.0.be-11.2.2 |
| **2.4.2** | [MODIFIED, MOVED FROM 11.1.2, LEVEL L1 > L3] Verify that business logic processes require realistic human timing, preventing excessively rapid transaction submissions. | 3 | v5.0.be-11.2.1 |

## References

For more information, see also:

* [OWASP Web Security Testing Guide 4.2: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README)
* Anti-automation can be achieved in many ways, including the use of the [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [OWASP Testing Guide 4.0: Input Validation Testing](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README.html)
* [OWASP Cheat Sheet: Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
* [JSON Schema](https://json-schema.org/specification.html)
