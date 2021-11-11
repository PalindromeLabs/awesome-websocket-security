# Awesome WebSockets Security

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A collection of CVEs, research, and reference materials related to WebSocket security

------

## Contents

- [WebSocket Library Vulnerabilities](#websocket_library_vulnerabilities)
- [Conference Talks](#conference_talks)
- [Common WebSocket Weaknesses](#common_weaknesses)
- [WebSocket Security Tools](#websocket_security_tools)
- [Bug Bounty Writeups](#bug_bounty_writeups)
- [Useful blog posts](#useful_blogs)

------

## <a name="websocket_library_vulnerabilities"></a>WebSocket Library Vulnerabilities

This list of vulnerabilities attempts to capture WebSocket CVEs and
related issues in commonly encountered WebSockets server implementations.

| CVE ID | Vulnerable package | Related writeup | Vulnerability summary |
| :---- | :---------- | :-------------------- | :------ |
| [CVE-2021-42340](https://nvd.nist.gov/vuln/detail/CVE-2021-42340) | [Tomcat](https://github.com/uNetworking/uWebSockets) | [Apache mailing list](https://lists.apache.org/thread.html/r83a35be60f06aca2065f188ee542b9099695d57ced2e70e0885f905c%40%3Cannounce.tomcat.apache.org%3E) | DoS memory leak |
| [CVE-2021-33880](https://nvd.nist.gov/vuln/detail/CVE-2021-33880) | [Python websockets](https://github.com/aaugustin/websockets) | [GitHub Advisory](https://github.com/advisories/GHSA-8ch4-58qp-g3mp) | HTTP basic auth timing attack |
| [CVE-2021-32640](https://nvd.nist.gov/vuln/detail/CVE-2021-32640) | [ws](https://github.com/websockets/ws) | [GitHub Advisory](https://github.com/websockets/ws/security/advisories/GHSA-6fc8-4gx4-v693) | Regex backtracking Denial of Service |
| [CVE-2020-36406](https://nvd.nist.gov/vuln/detail/CVE-2020-36406) | [uWebSockets](https://github.com/uNetworking/uWebSockets) | [OSS Fuzz Summary](https://github.com/google/oss-fuzz-vulns/blob/main/vulns/uwebsockets/OSV-2020-1695.yaml) | Stack buffer overflow |
| [CVE-2020-27813](https://nvd.nist.gov/vuln/detail/CVE-2020-27813) | [Gorilla](https://github.com/gorilla/websocket) | [GitHub Advisory](https://github.com/gorilla/websocket/security/advisories/GHSA-jf24-p9p9-4rjh) | Integer overflow |
| [CVE-2020-24807](https://nvd.nist.gov/vuln/detail/CVE-2020-24807) | [socket.io-file](https://github.com/rico345100/socket.io-file) | [Auxilium Security](https://blog.auxiliumcybersec.com/?p=2646) | File type restriction bypass |
| [CVE-2020-15779](https://nvd.nist.gov/vuln/detail/CVE-2020-15779) | [socket.io-file](https://github.com/rico345100/socket.io-file) | [Auxilium Security](https://blog.auxiliumcybersec.com/?p=2586) | Path traversal |
| [CVE-2020-15134](https://nvd.nist.gov/vuln/detail/CVE-2020-15134) | [faye-websocket](https://github.com/faye/faye-websocket-ruby) | [GitHub advisory](https://github.com/faye/faye/security/advisories/GHSA-3q49-h8f9-9fr9) | Lack of TLS certificate validation |
| [CVE-2020-15133](https://nvd.nist.gov/vuln/detail/CVE-2020-15133) | [faye-websocket](https://github.com/faye/faye-websocket-ruby) | [GitHub advisory](https://github.com/faye/faye-websocket-ruby/security/advisories/GHSA-2v5c-755p-p4gv) | Lack of TLS certificate validation |
| [CVE-2020-11050](https://nvd.nist.gov/vuln/detail/CVE-2020-11050) | [Java WebSocket](https://tootallnate.github.io/Java-WebSocket/) | [GitHub advisory](https://github.com/TooTallNate/Java-WebSocket/security/advisories/GHSA-gw55-jm4h-x339) | SSL hostname validation not performed |
| [CVE-2020-7663](https://nvd.nist.gov/vuln/detail/CVE-2020-7663) | [Ruby websocket-extensions](https://rubygems.org/gems/websocket-extensions) | [Writeup](https://blog.jcoglan.com/2020/06/02/redos-vulnerability-in-websocket-extensions/) | Regex backtracking Denial of Service |
| [CVE-2020-7662](https://nvd.nist.gov/vuln/detail/CVE-2020-7662) | [npm websocket-extensions](https://rubygems.org/gems/websocket-extensions) | [Writeup](https://snyk.io/blog/regular-expression-denial-of-service-in-websocket-extensions/) | Regex backtracking Denial of Service |
| None | [Socket.io](https://github.com/socketio/socket.io) | [GitHub Issue](https://github.com/socketio/socket.io/issues/3671) | CORS misconfiguration |
| [CVE-2018-1000518](https://nvd.nist.gov/vuln/detail/CVE-2018-1000518) | [Python websockets](https://github.com/aaugustin/websockets) | [GitHub PR](https://github.com/aaugustin/websockets/pull/407) | DoS via memory exhaustion when decompressing compressed data |
| None | [Tornado](https://github.com/tornadoweb/tornado) | [GitHub PR](https://github.com/tornadoweb/tornado/pull/2391) | DoS via memory exhaustion when decompressing compressed data |
| [CVE-2018-21035](https://nvd.nist.gov/vuln/detail/CVE-2018-21035) | [Qt WebSockets](https://doc.qt.io/qt-5/qtwebsockets-index.html) | [Bug report](https://bugreports.qt.io/browse/QTBUG-70693) | Denial of service due large limit on message and frame size |
| [CVE-2017-16031](https://nvd.nist.gov/vuln/detail/CVE-2017-16031) | [socket.io](https://socket.io/) | [GitHub Issue](https://github.com/socketio/socket.io/issues/856) | Socket IDs use predictable random numbers |
| [CVE-2016-10544](https://nvd.nist.gov/vuln/detail/CVE-2016-10544) | [uWebSockets](https://github.com/uNetworking/uWebSockets) | [npm advisory](https://www.npmjs.com/advisories/149) | Denial of service due to large limit on message size |
| [CVE-2016-10542](https://nvd.nist.gov/vuln/detail/CVE-2016-10542) | [NodeJS ws](https://www.npmjs.com/package/ws) | [npm advisory](https://www.npmjs.com/advisories/120) | Denial of service due to large limit on message size |
| None | [draft-hixie-thewebsocketprotocol-76](https://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76) | [Writeup](https://webcache.googleusercontent.com/search?q=cache:oPoZu0vomjYJ:https://www.ietf.org/mail-archive/web/hybi/current/msg04744.html+&cd=1&hl=en&ct=clnk&gl=us) |  |

------

## <a name="conference_talks"></a>Conference Talks, Papers, Notable Blog Posts

## 2011

- Talking to Yourself for Fun and Profit [Paper](http://www.adambarth.com/papers/2011/huang-chen-barth-rescorla-jackson.pdf)

### 2012

- Blackhat 2012 - Mike Shema, Sergey Shekyan, Vaagn Toukharian - Hacking with WebSockets [Video](https://www.youtube.com/watch?v=-ALjHUqSz_Y)

### 2019

- Hacktivity 2019 - Mikhail Egorov - What’s Wrong with WebSocket APIs? Unveiling Vulnerabilities in WebSocket APIs [Video](https://www.youtube.com/watch?v=gANzRo7UHt8)
- DerbyCon 2019 - Michael Fowl, Nick Defoe - Old Tools New Tricks Hacking WebSockets [Video](https://www.youtube.com/watch?v=MhxayMPknFI)

### 2021

- OWASP Global AppSec US 2021 - Erik Elbieh - We’re not in HTTP anymore: Investigating WebSocket Server Security [Paper](https://github.com/PalindromeLabs/STEWS/blob/main/paper.pdf) (video coming soon)


------

## <a name="common_websocket_weaknesses"></a>Common WebSocket Weaknesses

### Unencrypted WebSockets
<!-- markdown-link-check-disable-next-line -->
- Black Hills WebSocket testing guide: [Link](https://www.blackhillsinfosec.com/how-to-hack-websockets-and-socket-io/)

### Cross-Site WebSocket Hijacking (CSWSH)
- Original CSWSH blog post by Christian Schneider: [Link](https://christian-schneider.net/CrossSiteWebSocketHijacking.html)
- PortSwigger Web Academy CSWSH lab: [Link](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)

### Insecure Authentication Mechanism
- Stratum Security blog post: [Link](https://blog.stratumsecurity.com/2016/06/13/websockets-auth/)
- Heroku WebSocket Security: [Link](https://devcenter.heroku.com/articles/websocket-security#authentication-authorization)

### Reverse Proxy Bypass using Upgrade Header
- Mikhail Egorov's initial PoC from Hacktivity 2019: [Link](https://github.com/0ang3el/websocket-smuggle)
- Jake Miller's HTTP 2 smuggling tool based on Mikhail's PoC work: [Link](https://github.com/BishopFox/h2csmuggler)
- AssetNote blog post with golang h2smuggler tool: [Link](https://blog.assetnote.io/2021/03/18/h2c-smuggling/)

## DOM-based WebSocket-URL poisoning
- Portswigger summary: [Link](https://portswigger.net/web-security/dom-based/websocket-url-poisoning)

------

## <a name="useful_blogs"></a>Useful Blog Posts & Resources

- Portscanning using WebSockets [Link](https://medium.com/@stestagg/stealing-secrets-from-developers-using-websockets-254f98d577a0)
- WebSocket fuzzing with Kitty fuzzing framework [Link](https://snikt.net/blog/2019/05/22/to-fuzz-a-websocket/)
- WebSocket fuzzing harness [Link](https://vdalabs.com/2019/03/05/hacking-web-sockets-all-web-pentest-tools-welcomed/)
- Project Zero WebSockets-based buffer overflow [Link](https://googleprojectzero.blogspot.com/2020/02/several-months-in-life-of-part2.html)
- Reserved Extension, Subprotocol values [Link](https://www.iana.org/assignments/websocket/websocket.xml#subprotocol-name)

------

## <a name="websocket_security_tools"></a>WebSocket Security Tools

### Fuzzing
- websocket-fuzzer [GitHub](https://github.com/andresriancho/websocket-fuzzer)
- websocket-harness [GitHub](https://github.com/VDA-Labs/websocket-harness)

### Playgrounds
- DVWS: A purposefully vulnerable WebSocket demo [GitHub](https://github.com/interference-security/DVWS)
- WebSocket-Playground: Jumpstart multiple WebSockets servers [GitHub](https://github.com/PalindromeLabs/WebSockets-Playground)

### General Utilities & Tools

- WebSocket King [in-browser tool](https://websocketking.com/)
- Hoppscotch.io [in-browser tool](https://hoppscotch.io/realtime)
- websocat [GitHub](https://github.com/vi/websocat)
- wsd [GitHub](https://github.com/alexanderGugel/wsd)

------

## <a name="bug_bounty_writeups"></a>Bug Bounty Writeups

### CSWSH bugs

- [Slack H1 #207170](https://hackerone.com/reports/207170): CSWSH (plus [an additional writeup](https://labs.detectify.com/2017/02/28/hacking-slack-using-postmessage-and-websocket-reconnect-to-steal-your-precious-token/))
- [Facebook](https://ysamm.com/?p=363): CSWSH
- [Stripo H1 #915541](https://hackerone.com/reports/915541): CSWSH
- [Coda H1 #535436](https://hackerone.com/reports/535436): CSWSH
- [Legal Robot #211283](https://hackerone.com/reports/211283): CSWSH
- [Legal Robot H1 #274324](https://hackerone.com/reports/274324): CSWSH
- [Grammarly #395729](https://hackerone.com/reports/395729): CSWSH
- [Undisclosed target](https://sharan-panegav.medium.com/account-takeover-using-cross-site-websocket-hijacking-cswh-99cf9cea6c50): CSWSH
- [Undisclosed target](https://medium.com/bugbountywriteup/one-token-to-leak-them-all-the-story-of-a-8000-npm-token-79b13af182a3): CSWSH

### Other bugs

- [PlayStation H1 #873614](https://hackerone.com/reports/873614): Remote code execution over WebSockets
- [Shopify H1 #409701](https://hackerone.com/reports/409701): SSRF over WebSockets
- [QIWI H1 #512065](https://hackerone.com/reports/512065): DOM XSS over WebSockets
- [NodeJS H1 #868834](https://hackerone.com/reports/868834): DoS because no timeout to close unresponsive connections
- [Bitwala H1 #862835](https://hackerone.com/reports/862835): Broken authentication
- [Shopify H1 #1023669](https://hackerone.com/reports/1023669): Broken authentication
- [Legal Robot H1 #163464](https://hackerone.com/reports/163464): Information leak
- [GitHub H1 #854439](https://hackerone.com/reports/854439): Arbitrary SQL queries via injection
- [Undisclosed target](https://footstep.ninja/posts/idor-via-websockets/): IDOR over WebSockets
- [Undisclosed target on BugCrowd](https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa): XSS over WebSockets
