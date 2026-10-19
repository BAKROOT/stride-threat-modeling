#!/usr/bin/env python3
"""OrbitPay threat model as code (OWASP pytm) - webhook and checkout path.

Companion to README Section 14.2 and examples/orbitpay/threats.yaml.

    pip install pytm
    python3 orbitpay_tm.py --dfd | dot -Tpng -o dfd.png       # data flow diagram
    python3 orbitpay_tm.py --seq | java -jar plantuml.jar -p > seq.png
    python3 orbitpay_tm.py --report pytm_report_template.md > report.md

pytm's attribute names evolve between releases; this file targets pytm 1.4,
where security properties live under element.controls and a flow inherits its
protocol, port and transport encryption from the element it connects to.
The attributes set below (authentication, encryption, sanitisation) drive which
of pytm's built-in rules fire, so they are written to reflect the CURRENT,
pre-mitigation design described in the threat register (for example, F9 has
no message authentication: threat T-02).
"""
from pytm import TM, Actor, Boundary, Classification, Data, Dataflow, Datastore, Lambda, Process, Server

tm = TM("OrbitPay - checkout and payment webhook path")
tm.description = "Checkout, PSP integration and webhook handling (TM-001 excerpt)"
tm.isOrdered = True
tm.mergeResponses = True
tm.assumptions = [
    "A-01 Cloud provider physical, hypervisor and managed-service security is trusted",
    "A-02 Raw PANs never reach OrbitPay; PSP hosted fields capture card data",
    "A-03 TLS terminates at P1; internal traffic uses mTLS via the service mesh",
]

# Trust boundaries --------------------------------------------------------
internet = Boundary("TB1 Internet")
dmz = Boundary("TB2 DMZ")
internal = Boundary("TB3 Internal mesh")
third_party = Boundary("TB4 Third parties")
data_tier = Boundary("TB5 Data tier")

# Data --------------------------------------------------------------------
order = Data("Order and amount", classification=Classification.RESTRICTED)
webhook_event = Data("PSP payment event", classification=Classification.RESTRICTED)
pii = Data("Customer PII", classification=Classification.SENSITIVE)

# Elements ----------------------------------------------------------------
customer = Actor("E1 Customer")
customer.inBoundary = internet

psp = Actor("E3 Payment Service Provider")
psp.inBoundary = third_party
psp.port = 443
psp.protocol = "HTTPS"
psp.controls.isEncrypted = True

gateway = Server("P1 API Gateway and WAF")
gateway.inBoundary = dmz
gateway.OS = "Managed gateway"
gateway.port = 443
gateway.protocol = "HTTPS"
gateway.controls.isEncrypted = True
gateway.controls.isHardened = True
gateway.controls.sanitizesInput = True
gateway.controls.encodesOutput = True
gateway.controls.hasAccessControl = True

webhook = Lambda("P4 Webhook Handler")
webhook.inBoundary = dmz
webhook.port = 443
webhook.protocol = "HTTPS"
webhook.controls.isEncrypted = True
webhook.controls.hasAccessControl = False      # IP allow-list only (T-02)
webhook.controls.checksInputBounds = False

payments = Process("P3 Payments Service")
payments.inBoundary = internal
payments.port = 8443
payments.protocol = "HTTPS (mTLS)"
payments.controls.isEncrypted = True
payments.codeType = "Managed"
payments.controls.usesParameterizedInput = True
payments.controls.implementsAuthenticationScheme = True
payments.controls.hasAccessControl = True
payments.controls.sanitizesInput = False       # trusts client-supplied amount (T-04)
payments.controls.validatesInput = False

db = Datastore("DS1 Payments DB")
db.inBoundary = data_tier
db.port = 5432
db.protocol = "PostgreSQL over TLS"
db.controls.isEncrypted = True
db.isSQL = True
db.controls.isEncryptedAtRest = True
db.storesPII = True
db.isShared = False
db.storesSensitiveData = True
db.hasWriteAccess = True

# Data flows --------------------------------------------------------------
f1 = Dataflow(customer, gateway, "F1 Checkout request")
f1.data = [order, pii]
f1.controls.authenticatesSource = True     # JWT validated at P1

f3 = Dataflow(gateway, payments, "F3 Checkout call")
f3.data = [order]

f6 = Dataflow(payments, db, "F6 Read/write orders")
f6.data = [order, pii]

f8 = Dataflow(payments, psp, "F8 Charge request")
f8.data = [order]
f8.note = "Certificate verification must be enforced (T-24)"

f9 = Dataflow(psp, webhook, "F9 Payment webhook")
f9.data = [webhook_event]
f9.controls.authenticatesSource = False    # no signature verification yet (T-02)
f9.controls.providesIntegrity = False
f9.note = "Must verify PSP signature, timestamp and event ID; verify by fetch (T-02)"

f10 = Dataflow(webhook, payments, "F10 Status update")
f10.data = [webhook_event]

if __name__ == "__main__":
    tm.process()
