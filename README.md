# Next.Js React Server Components (RSC) Vulnerabilities

This repository contains research notes and technical analysis of multiple security vulnerabilities affecting **React Server Components (RSC)** and **Next.js App Router** implementations.  
The issues described below impact the RSC Flight protocol and Server Functions (Server Actions), and may lead to **remote code execution**, **source code disclosure**, or **denial of service** under certain conditions.

---

## Overview of affected projects

React Server Components rely on an internal serialization protocol known as **React Flight** to exchange data between the client and the server.  
Next.js builds on top of this protocol to implement:

- App Router (folders `/app` or `/src/app` in project)
- Vulnerable version of Next.Js

Projects with page router not vulnerable to all of this CVEs.

For `CVE-2025-55183` there is additional conditions:

- Server Functions / Server Actions (check `vulnerable_app/app/action.ts`)
- This function explicitly or implicitly exposes a stringified argument

Several vulnerabilities were identified in how **untrusted HTTP input** is deserialized and processed by the RSC runtime.

---

## Vulnerable stand deployment

To test this CVEs you can use vulnerable app:
```bash
cd vulnerable_app
docker-compose up -d --build
```

Then open http://localhost:3000/test123

---

## CVE-2025-55182 — React Server Components Remote Code Execution

### Description

CVE-2025-55182 is a **pre-authentication remote code execution (RCE)** vulnerability caused by unsafe deserialization logic in the React Flight protocol.

By sending a specially crafted HTTP `POST` request to a Server Function endpoint, an attacker may exploit **prototype pollution** during Flight payload deserialization.  
This can result in arbitrary JavaScript execution on the server.

This vulnerability has been reported as **actively exploited in the wild**.

The vulnerability exists in the React Flight protocol's deserialization logic. By sending a malicious payload via HTTP POST, an attacker can achieve prototype pollution that leads to arbitrary code execution on the server.

https://github.com/sickwell/CVE-2025-55182/blob/main/cve-2025-55182.yaml

---

## CVE-2025-55183 - Server Function Source Code Disclosure

A source code disclosure vulnerability in Next.js React Server Components (RSC). A malicious HTTP request sent to a vulnerable Server Function may unsafely return the source code of any Server Function when the argument is stringified.

---

## CVE-2025-55184 - Server Components Denial of Service

Insecure deserialization vulnerability caused by unsafe payload deserialization in Server Function endpoints, letting unauthenticated attackers cause denial of service by hanging the server process.

### Detection


---

## Possible WAF bypass


---

## References

- [Vercel blog (Security Bulletin: CVE-2025-55184 and CVE-2025-55183)](https://vercel.com/kb/bulletin/security-bulletin-cve-2025-55184-and-cve-2025-55183#patched-versions)

- []()