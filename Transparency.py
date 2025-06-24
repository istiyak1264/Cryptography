# website: https://cryptohack.org/challenges/general/
# problem name: Transparency

from Crypto.PublicKey import RSA
with open("transparency.pem", "r") as f:
    Key = f.read()
    print(Key)
    Key = RSA.import_key(Key)


#let's enumerate subdomain of cryptohack.org using amass
#istiyak@kali:~ amass enum -d cryptohack.org 
"""             
cryptohack.org (FQDN) --> mx_record --> mxb.eu.mailgun.org (FQDN)
cryptohack.org (FQDN) --> mx_record --> mxa.eu.mailgun.org (FQDN)
cryptohack.org (FQDN) --> a_record --> 178.62.74.206 (IPAddress)
web.cryptohack.org (FQDN) --> cname_record --> aes.cryptohack.org (FQDN)
www.cryptohack.org (FQDN) --> cname_record --> cryptohack.org (FQDN)
blog.cryptohack.org (FQDN) --> cname_record --> hyperreality.github.io (FQDN)
178.62.64.0/18 (Netblock) --> contains --> 178.62.74.206 (IPAddress)
14061 (ASN) --> managed_by --> DIGITALOCEAN-ASN - DigitalOcean, LLC (RIROrganization)
14061 (ASN) --> announces --> 178.62.64.0/18 (Netblock)
cryptohack.org (FQDN) --> ns_record --> ns1.digitalocean.com (FQDN)
cryptohack.org (FQDN) --> ns_record --> ns2.digitalocean.com (FQDN)
cryptohack.org (FQDN) --> ns_record --> ns3.digitalocean.com (FQDN)
aes.cryptohack.org (FQDN) --> a_record --> 178.62.74.206 (IPAddress)
ns1.digitalocean.com (FQDN) --> a_record --> 172.64.52.210 (IPAddress)
ns1.digitalocean.com (FQDN) --> aaaa_record --> 2606:4700:52::ac40:34d2 (IPAddress)
tls1.cryptohack.org (FQDN) --> a_record --> 178.62.74.206 (IPAddress)
tls2.cryptohack.org (FQDN) --> a_record --> 178.62.74.206 (IPAddress)
tls3.cryptohack.org (FQDN) --> a_record --> 178.62.74.206 (IPAddress)
****thetransparencyflagishere.cryptohack.org (FQDN) --> a_record --> 178.62.74.206 (IPAddress)****
172.64.0.0/18 (Netblock) --> contains --> 172.64.52.210 (IPAddress)
13335 (ASN) --> managed_by --> CLOUDFLARENET - Cloudflare, Inc. (RIROrganization)
13335 (ASN) --> announces --> 172.64.0.0/18 (Netblock)
ns2.digitalocean.com (FQDN) --> a_record --> 172.64.53.21 (IPAddress)
ns2.digitalocean.com (FQDN) --> aaaa_record --> 2606:4700:5a::ac40:3515 (IPAddress)
ns3.digitalocean.com (FQDN) --> a_record --> 172.64.49.209 (IPAddress)
ns3.digitalocean.com (FQDN) --> aaaa_record --> 2606:4700:52::ac40:31d1 (IPAddress)
172.64.0.0/18 (Netblock) --> contains --> 172.64.53.21 (IPAddress)
172.64.0.0/18 (Netblock) --> contains --> 172.64.49.209 (IPAddress)
2606:4700:52::/48 (Netblock) --> contains --> 2606:4700:52::ac40:34d2 (IPAddress)
2606:4700:52::/48 (Netblock) --> contains --> 2606:4700:52::ac40:31d1 (IPAddress)
2606:4700:5a::/48 (Netblock) --> contains --> 2606:4700:5a::ac40:3515 (IPAddress)
13335 (ASN) --> announces --> 2606:4700:52::/48 (Netblock)
13335 (ASN) --> announces --> 2606:4700:5a::/48 (Netblock)

The enumeration has finished
"""

#thetransparencyflagishere.cryptohack.org (FQDN) --> a_record --> 178.62.74.206 (IPAddress)
#this is the subdomain where the flag is available.