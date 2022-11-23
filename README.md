Collection of my Nuclei Templates. If I can validate a template for false positives I will create a pull request to https://github.com/projectdiscovery/nuclei-templates. The templates here are templates that I do not validate, so false positives a likely going to occur.

## jwks.json
This filter will check if `/jwks.json` or `/.well-known/jsk.json` is exposed. This is not a security threat if only public keys are exposed, but sometimes developers may exposed private keys in this file as well. Even if no secret key components are exposed, the knowledge of public keys may be useful for other attacks, such as algorithm and key confusion for example. 
- https://portswigger.net/kb/issues/00600700_json-web-key-set-disclosed
- https://portswigger.net/web-security/jwt/algorithm-confusion


## envoy-metadata-disclosure
Due to incorrect configuration, Enovy proxy discloses sensitive information about the target in the "x-envoy-peer-metadata" response header.
- https://www.acunetix.com/vulnerabilities/web/envoy-metadata-disclosure/
- https://stackoverflow.com/questions/68829411/turn-off-or-remove-x-envoy-peer-metadata
- https://medium.com/pentesternepal/interesting-stored-xss-via-meta-data-eb8fe1de8b33
