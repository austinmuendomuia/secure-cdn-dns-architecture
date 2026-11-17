# StaffOnly CDN & IAM Subsystem

A secure cloud infrastructure and Identity & Access Management (IAM) backend deployed for our third-year CDN group project.

## Team
* **Austin:** Infrastructure & DNS Lead
* **Allan:** Security & Backend (IAM & Billing)
* **Joe:** UX & Project Director

## Infrastructure Architecture
* **Cloud Provider:** Microsoft Azure
* **OS:** Ubuntu 22.04 LTS (B2ats_v2)
* **Web Server / Reverse Proxy:** Nginx
* **Domain & DNS:** `staffonly.me` (Routed via Namecheap Advanced DNS)
* **Security:** 
  * Strict Azure Network Security Group (NSG) rules enforcing ports 22, 80, and 443.
  * UFW internal firewall enabled for 'Nginx Full'.
  * Full TLS/SSL encryption via ZeroSSL with automated HTTP to HTTPS redirection.

## Deployment Status
- [x] Provision Azure VM and IP routing
- [x] Configure Namecheap DNS and CNAME validation
- [x] Install and configure Nginx
- [x] Generate and apply ZeroSSL certificates (`fullchain.crt`, `private.key`)
- [ ] Deploy IAM & Billing Backend
