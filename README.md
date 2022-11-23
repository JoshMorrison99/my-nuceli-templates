Collection of my Nuclei Templates. If I can validate a template for false positives I will create a pull request to https://github.com/projectdiscovery/nuclei-templates. The templates here are templates that I do not validate, so false positives a likely going to occur. Create an issue if a false positive occurs and I'll see what I can do.

## jwks.json
This filter will check if `/jwks.json` or `/.well-known/jsk.json` is exposed. This is not a security threat if only public keys are exposed, but sometimes developers may exposed private keys in this file as well. Even if no secret key components are exposed, the knowledge of public keys may be useful for other attacks, such as algorithm and key confusion for example. 
- https://portswigger.net/kb/issues/00600700_json-web-key-set-disclosed
- https://portswigger.net/web-security/jwt/algorithm-confusion


## envoy-metadata-disclosure
Due to incorrect configuration, Enovy proxy discloses sensitive information about the target in the "x-envoy-peer-metadata" response header.
- https://www.acunetix.com/vulnerabilities/web/envoy-metadata-disclosure/
- https://stackoverflow.com/questions/68829411/turn-off-or-remove-x-envoy-peer-metadata
- https://medium.com/pentesternepal/interesting-stored-xss-via-meta-data-eb8fe1de8b33

## CVE-2020-14815
XSS in Oracle Business Intelligence. This template is credited to `pikpikcu`. It has false positives, but still worth a try.
- https://twitter.com/HackerOn2Wheels/status/1326927875279380480
- https://github.com/projectdiscovery/nuclei-templates/commit/c7aa1e5b1202e95c803d83d044fbbe46449565c9
- https://github.com/projectdiscovery/nuclei-templates/issues/1024

## CVE-2021-22881
The Host Authorization middleware in Action Pack before 6.1.2.1, 6.0.3.5 suffers from an open redirect vulnerability. Specially crafted `Host` headers in combination with certain "allowed host" formats can cause the Host Authorization middleware in Action Pack to redirect users to a malicious website. Impacted applications will have allowed hosts with a leading dot. When an allowed host contains a leading dot, a specially crafted `Host` header can be used to redirect to a malicious website.
- https://hackerone.com/reports/1374512
- https://nvd.nist.gov/vuln/detail/CVE-2021-22881
