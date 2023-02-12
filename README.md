Collection of my Nuclei Templates. If I can validate a template for false positives I will create a pull request to https://github.com/projectdiscovery/nuclei-templates. Most of the templates here are templates that I do not validate, so false positives a likely going to occur. Create an issue if a false positive occurs and I'll see what I can do. None of the templates created will test for DoS.

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

## CVE-2021-26722
All credit goes to `pikpikcu`. There was an error when compiling `pikpikcu's` previous script `line 10: field issues not found in type model.Info`. I just removed the `issues` field. LinkedIn Oncall through 1.4.0 allows reflected XSS via /query because of mishandling of the "No results found for" message in the search bar.
- https://github.com/linkedin/oncall/issues/341

## CVE-2021-24351
All credit goes to Maximus Decimus. Template found here: https://github.com/projectdiscovery/nuclei-templates/issues/6200
  - https://wpscan.com/vulnerability/2ee62f85-7aea-4b7d-8b2d-5d86d9fb8016
  - https://nvd.nist.gov/vuln/detail/CVE-2021-24351
  
## tiny-file-manager-default-login
Tiny file manager has a default login of admin:admin@123. This repository has 3.4k stars on GitHub. The motivation for creating this template is this hackerone report: https://hackerone.com/reports/1747146. PR has been created: https://github.com/projectdiscovery/nuclei-templates/pull/6299

## ThinkPHP-RCE
ThinkPHP <6.0.14 RCE - No clue if this is even true, but I've seen a few tweets about it, so here is the nuclei template. 
- https://twitter.com/TodayCyberNews/status/1601209967872442370
- https://twitter.com/cyberkendra/status/1601178498806472705

## PHP/8.1.0-dev
An early release of PHP, the PHP 8.1.0-dev version was released with a backdoor on March 28th 2021, but the backdoor was quickly discovered and removed. If this version of PHP runs on a server, an attacker can execute arbitrary code by sending the User-Agentt header.
- https://www.youtube.com/watch?v=j-wmhJ8u5Ws&ab_channel=JohnHammond

## salesforce-misconfiguration
Detects Salesforce misconfigured/exposed objects. Once the objects are detected, it may require more work to find vulnerabilities depending on what type of object is exposed. Here is my work on the subject: https://github.com/JoshMorrison99/Salesforce-Misconfigured-Objects/edit/main/README.md
![image](https://user-images.githubusercontent.com/25315255/206927759-d6d0c385-f80a-47e2-9616-7fba6fad7d5b.png)
- https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-1-the-essentials-ffae632a00e5
- https://infosecwriteups.com/in-simple-words-pen-testing-salesforce-saas-application-part-2-fuzz-exploit-eefae11ba5ae
- https://www.varonis.com/blog/abusing-salesforce-communities
- https://pentestmag.com/making-small-things-big/

## salesforce-aura
Used to detect salesforce aura API. This is used as a base template in the Salesforce workflow to advance to other salesforce misonfigurations.

## exposed-merge-metadata-servlet
This can be detected with https://github.com/0ang3el/aem-hacker, but it will give false positive since it is not checking if the response is `text/html`. The vulnerability is Exposed MergeMetadataServlet and can be read more about here:
- https://labs.withsecure.com/publications/securing-aem-with-dispatcher

## x-forwarded-for
All credit goes to `aufzayed`. x-forwarded-for is a common bypass for 403.

## CVE-2022-38628
All credit goes to `omarhashem123`. Follow him on twitter here: https://twitter.com/OmarHashem666
- https://github.com/omarhashem123/Security-Research/tree/main/CVE-2022-38628
- https://twitter.com/OmarHashem666/status/1602415798206795782

## CVE-2022-46381
All credit goes to `omarhashem123`. Follow him on twitter here: https://twitter.com/OmarHashem666
- https://github.com/omarhashem123/Security-Research/tree/main/CVE-2022-46381
- https://twitter.com/OmarHashem666/status/1602415798206795782

## CVE-2022-46169
This template is more used for finderprinting the technology of `CVE-2022-46169` rather than actually exploiting it. If this template goes get triggered, then it is a good idea to follow the steps outlined in the PoC below to try and exploit it. If you do end up finding a vulnerable website, you can use this metasploit module to exploit it: https://twitter.com/WynterErik/status/1605958628938108928
- https://github.com/0xf4n9x/CVE-2022-46169

## CVE-2022-2414
XXE vulnerability - A flaw was found in pki-core. Access to external entities when parsing XML documents can lead to XML external entity (XXE) attacks. This flaw allows a remote attacker to potentially retrieve the content of arbitrary files by sending specially crafted HTTP requests.
- https://github.com/amitlttwo/CVE-2022-2414-Proof-Of-Concept

## CVE-2022-21661
This vulnerability allows remote attackers to disclose sensitive information on affected installations of WordPress Core, Authentication is not required to exploit this vulnerability, The specific flaw exists within the WP_Query class, The issue results from the lack of proper validation of a user-supplied string before using it to construct SQL queries, An attacker can leverage this vulnerability to disclose stored credentials, leading to further compromise.
- https://www.exploit-db.com/exploits/50663
- https://github.com/APTIRAN/CVE-2022-21661

## CVE-2018-11759
This CVE is already in the main nuclei template repository, but I added onto it due to this tweet: https://twitter.com/0x_rood/status/1603473550714802181. The additional check is for `jk_status`.

## vhost-discovery
This template can be used to find vhost. It does bruteforce of 1000 common vhosts names.

## wp-duplicator-path-traversal
PoC available here: https://github.com/Mad-robot/wordpress-exploits/blob/master/plugins/duplicator%20Path%20Traversal.md?plain=1

## CVE-2019-16891
Liferay Portal 7.1.0 and earlier is vulnerable to remote code execution (RCE) via deserialization of JSON data. This template will produce some false positives. 
- https://dappsec.substack.com/p/an-advisory-for-cve-2019-16891-from
- https://twitter.com/therceman/status/1605617685106085893

## microweber-xss
- https://huntr.dev/bounties/1fb2ce08-7016-45fa-b402-ec08d700e4df/
- https://github.com/microweber/microweber

## kanboard-default-login
Kanboard is project management software that focuses on the Kanban methodology. It has around 7k stars on GitHub. Default Login is admin:admin. Created a pull request to main repository.
- https://github.com/projectdiscovery/nuclei-templates/pull/6435

## nexus-detect
Through some google dorking I found that a lot of companies host their nexus repositories at the /nexus endpoint. I added the line to check that endpoint.

## nexus-oss-detect
This template is used to check for older versions of nexus repository manager.

## node-env
This template looks for `NODE_ENV` keyword. In NodeJS, NODE_ENV commonly holds sensitive information.

## django-debug-exposed-404
This template look for Django Debug mode set to True by checking for default 404 pages

## django-debug-exposure-csrf
This template look for Django Debug mode set to True by checking for default CSRF pages

## rails-routes-exposed
This template looks for the Ruby on Rails routes endpoint
