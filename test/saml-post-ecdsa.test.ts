import { describe, it, expect } from "vitest";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import { ExclusiveCanonicalization } from "xml-crypto/lib/exclusive-canonicalization.js";
import { verifyPostSignature } from "../src/lib/saml/authn-request.js";
import { TEST_SAML_SP_CERT_PEM, TEST_SAML_SP_KEY_PKCS8 } from "./fixtures/saml-keys.js";
import type { SamlServiceProviderRow } from "../src/types.js";

// Live fixtures captured from the SAMLscope metadata campaign (IIP-ALG03).
// REQ carries a valid ecdsa-sha256 signature; BAD is the suite's corrupted
// negative control signed with the same EC key.
const REQ = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="https://relatives-expressions-bbs-engage.trycloudflare.com/p/plan_60TE3CPPH0T57BE1GY3AMM7XW0/sp/acs/0?mdv=ecdsa-sha256&amp;run=run_GRB2114AYHAKDQ4WPAZC5MMZYY" Destination="https://idp.tmesandbox.com/saml/sso" ID="_metadata_5GA1TDK29ZDCS7CXQEAX1AHS9Y" IssueInstant="2026-11-20T01:22:15.189785251Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer>https://relatives-expressions-bbs-engage.trycloudflare.com/p/plan_60TE3CPPH0T57BE1GY3AMM7XW0</saml:Issuer><ds:Signature>\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>\n<ds:Reference URI="#_metadata_5GA1TDK29ZDCS7CXQEAX1AHS9Y">\n<ds:Transforms>\n<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>\n<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n<ds:DigestValue>jYTaBxO4jChP5KmgQZESmlh7OQAJQMPTt2h2LnlMoto=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>\ndhTiagf4Jr7dH3TjnJXvWSSTGaZz4L4VdL8AAf8nxKqxBxEDhCRIzwZZHb+i6o8c0FrW7QBA1YFa&#13;\nJpuyn3lR/g==\n</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>\nMIICMTCCAdegAwIBAgIVAJR/0TstCxoSJsuCEgR0/HH4yVsxMAoGCCqGSM49BAMCMIGGMUYwRAYD&#13;\nVQQDDD1zYW1sc2NvcGUgZWMtZjBlY2I5ZTJmYTUyYTc1YmNiNmMyYzNjIHRlc3Qga2V5IChETyBO&#13;\nT1QgVFJVU1QpMSgwJgYDVQQLDB9wbGFuXzYwVEUzQ1BQSDBUNTdCRTFHWTNBTU03WFcwMRIwEAYD&#13;\nVQQKDAlzYW1sc2NvcGUwHhcNMjYxMTE5MDEyMjEzWhcNMjcxMTIwMDEyMjEzWjCBhjFGMEQGA1UE&#13;\nAww9c2FtbHNjb3BlIGVjLWYwZWNiOWUyZmE1MmE3NWJjYjZjMmMzYyB0ZXN0IGtleSAoRE8gTk9U&#13;\nIFRSVVNUKTEoMCYGA1UECwwfcGxhbl82MFRFM0NQUEgwVDU3QkUxR1kzQU1NN1hXMDESMBAGA1UE&#13;\nCgwJc2FtbHNjb3BlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnsG8MywKA4Q0h7bgpRQhqJEY&#13;\nFoGEUziEjj+bGx2HQfp+rNUZU7TlXekKGMt40yL3nKaQ0A1MlukvLHrk9cbFw6MgMB4wDAYDVR0T&#13;\nAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIgAZy6zYOkk0Hs3jq9Wqy5&#13;\nA15M/7dqY3LNp3xo1RxazSsCIQDvtgZNj7SVTRDhsxmLdZ6h54GiWYxoh/YqtShOdyVBaQ==\n</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/></samlp:AuthnRequest>';
const BAD = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" AssertionConsumerServiceURL="https://relatives-expressions-bbs-engage.trycloudflare.com/p/plan_60TE3CPPH0T57BE1GY3AMM7XW0/sp/acs/0?mdv=ecdsa-sha256-invalid-signature&amp;run=run_GRB2114AYHAKDQ4WPAZC5MMZYY" Destination="https://idp.tmesandbox.com/saml/sso" ID="_metadata_SHXR4D4Z2WHSWP2R0HVWVPAJKB" IssueInstant="2026-11-20T01:22:18.997636378Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"><saml:Issuer>https://relatives-expressions-bbs-engage.trycloudflare.com/p/plan_60TE3CPPH0T57BE1GY3AMM7XW0</saml:Issuer><ds:Signature>\n<ds:SignedInfo>\n<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>\n<ds:Reference URI="#_metadata_SHXR4D4Z2WHSWP2R0HVWVPAJKB">\n<ds:Transforms>\n<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>\n<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n</ds:Transforms>\n<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n<ds:DigestValue>S0jG61zTTtcr+95gUmatI8OpPqt7K7/tjkzfp1apwZE=</ds:DigestValue>\n</ds:Reference>\n</ds:SignedInfo>\n<ds:SignatureValue>A9to5PHh+uVmiQ8rvu1u25TToCXMp32YRd5OKZdNYVy/ADyj7ugOGuv1lXzHJAaetbTAuWmAB8I/&#13;\nMliceT0+4w==</ds:SignatureValue>\n<ds:KeyInfo>\n<ds:X509Data>\n<ds:X509Certificate>\nMIICMTCCAdegAwIBAgIVAJR/0TstCxoSJsuCEgR0/HH4yVsxMAoGCCqGSM49BAMCMIGGMUYwRAYD&#13;\nVQQDDD1zYW1sc2NvcGUgZWMtZjBlY2I5ZTJmYTUyYTc1YmNiNmMyYzNjIHRlc3Qga2V5IChETyBO&#13;\nT1QgVFJVU1QpMSgwJgYDVQQLDB9wbGFuXzYwVEUzQ1BQSDBUNTdCRTFHWTNBTU03WFcwMRIwEAYD&#13;\nVQQKDAlzYW1sc2NvcGUwHhcNMjYxMTE5MDEyMjEzWhcNMjcxMTIwMDEyMjEzWjCBhjFGMEQGA1UE&#13;\nAww9c2FtbHNjb3BlIGVjLWYwZWNiOWUyZmE1MmE3NWJjYjZjMmMzYyB0ZXN0IGtleSAoRE8gTk9U&#13;\nIFRSVVNUKTEoMCYGA1UECwwfcGxhbl82MFRFM0NQUEgwVDU3QkUxR1kzQU1NN1hXMDESMBAGA1UE&#13;\nCgwJc2FtbHNjb3BlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnsG8MywKA4Q0h7bgpRQhqJEY&#13;\nFoGEUziEjj+bGx2HQfp+rNUZU7TlXekKGMt40yL3nKaQ0A1MlukvLHrk9cbFw6MgMB4wDAYDVR0T&#13;\nAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIgAZy6zYOkk0Hs3jq9Wqy5&#13;\nA15M/7dqY3LNp3xo1RxazSsCIQDvtgZNj7SVTRDhsxmLdZ6h54GiWYxoh/YqtShOdyVBaQ==\n</ds:X509Certificate>\n</ds:X509Data>\n</ds:KeyInfo>\n</ds:Signature><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/></samlp:AuthnRequest>';
const PEM = '-----BEGIN CERTIFICATE-----\nMIICMTCCAdegAwIBAgIVAJR/0TstCxoSJsuCEgR0/HH4yVsxMAoGCCqGSM49BAMC\nMIGGMUYwRAYDVQQDDD1zYW1sc2NvcGUgZWMtZjBlY2I5ZTJmYTUyYTc1YmNiNmMy\nYzNjIHRlc3Qga2V5IChETyBOT1QgVFJVU1QpMSgwJgYDVQQLDB9wbGFuXzYwVEUz\nQ1BQSDBUNTdCRTFHWTNBTU03WFcwMRIwEAYDVQQKDAlzYW1sc2NvcGUwHhcNMjYx\nMTE5MDEyMjEzWhcNMjcxMTIwMDEyMjEzWjCBhjFGMEQGA1UEAww9c2FtbHNjb3Bl\nIGVjLWYwZWNiOWUyZmE1MmE3NWJjYjZjMmMzYyB0ZXN0IGtleSAoRE8gTk9UIFRS\nVVNUKTEoMCYGA1UECwwfcGxhbl82MFRFM0NQUEgwVDU3QkUxR1kzQU1NN1hXMDES\nMBAGA1UECgwJc2FtbHNjb3BlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnsG8\nMywKA4Q0h7bgpRQhqJEYFoGEUziEjj+bGx2HQfp+rNUZU7TlXekKGMt40yL3nKaQ\n0A1MlukvLHrk9cbFw6MgMB4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4Aw\nCgYIKoZIzj0EAwIDSAAwRQIgAZy6zYOkk0Hs3jq9Wqy5A15M/7dqY3LNp3xo1Rxa\nzSsCIQDvtgZNj7SVTRDhsxmLdZ6h54GiWYxoh/YqtShOdyVBaQ==\n-----END CERTIFICATE-----\n';
const SP = { signing_certs: JSON.stringify([PEM]) } as unknown as SamlServiceProviderRow;

describe("post-binding ecdsa verification", () => {
  it("accepts the valid ecdsa-sha256 AuthnRequest", async () => {
    expect(await verifyPostSignature(SP, REQ, { id: "_metadata_5GA1TDK29ZDCS7CXQEAX1AHS9Y", issuer: "x", acsUrl: null } as never)).toBe("ok");
  });
  it("rejects the corrupted ecdsa-sha256 AuthnRequest", async () => {
    expect(await verifyPostSignature(SP, BAD, { id: "_metadata_SHXR4D4Z2WHSWP2R0HVWVPAJKB", issuer: "x", acsUrl: null } as never)).toBe("bad");
  });
});

const NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const REQ_ID = "_metadata_5GA1TDK29ZDCS7CXQEAX1AHS9Y";
const parsed = { id: REQ_ID, issuer: "x", acsUrl: null } as never;

// xml-crypto selects SignatureMethod/DigestMethod/Transform by local-name
// under ANY namespace, first in document order, while the route's allowlist
// only inspected ds:-namespaced elements. A foreign-namespaced decoy must be
// rejected outright - even one naming an allowlisted algorithm.
describe("post-binding namespace decoys", () => {
  it("rejects a foreign-namespace SignatureMethod decoy", async () => {
    const decoyed = REQ.replace(
      "<ds:Signature>",
      '<ds:Signature><x:SignatureMethod xmlns:x="urn:decoy" Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>',
    );
    expect(await verifyPostSignature(SP, decoyed, parsed)).toBe("bad");
  });

  it("rejects a foreign-namespace DigestMethod decoy", async () => {
    const decoyed = REQ.replace(
      '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>',
      '<x:DigestMethod xmlns:x="urn:decoy" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>',
    );
    expect(await verifyPostSignature(SP, decoyed, parsed)).toBe("bad");
  });

  it("rejects an rsa-sha1 signature hidden behind a SignatureMethod decoy", async () => {
    // The full attack shape: SignedInfo declares allowlisted rsa-sha256, the
    // SignatureValue is a genuine RSA-SHA1 signature, and an <x:SignatureMethod
    // Algorithm="rsa-sha1"> before SignedInfo makes xml-crypto verify it as
    // SHA-1 while a ds:-only allowlist sees the conformant ds:SignatureMethod.
    const id = "_sha1decoyreq";
    const unsigned =
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="${NS_DS}"` +
      ` ID="${id}" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" AssertionConsumerServiceURL="https://sp.example/acs">` +
      `<saml:Issuer>https://sp.example/entity</saml:Issuer></samlp:AuthnRequest>`;
    const signer = new SignedXml({
      privateKey: TEST_SAML_SP_KEY_PKCS8,
      signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
    });
    signer.addReference({
      xpath: "//*[local-name(.)='AuthnRequest']",
      transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
      digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    });
    signer.computeSignature(unsigned, { location: { reference: "//*[local-name(.)='Issuer']", action: "after" } });
    const signed = signer.getSignedXml();

    const doc = new DOMParser().parseFromString(signed, "text/xml");
    const signedInfo = doc.getElementsByTagNameNS(NS_DS, "SignedInfo")[0]!;
    const canon = new ExclusiveCanonicalization().process(signedInfo).toString();
    const pkcs8 = Uint8Array.from(atob(TEST_SAML_SP_KEY_PKCS8.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" }, false, ["sign"]);
    const sha1Sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(canon)))));
    const sha1Signed = signed.replace(/<SignatureValue>[^<]*<\/SignatureValue>/, `<SignatureValue>${sha1Sig}</SignatureValue>`);

    const sp = { signing_certs: JSON.stringify([TEST_SAML_SP_CERT_PEM]) } as unknown as SamlServiceProviderRow;
    const req = { id, issuer: "x", acsUrl: null } as never;
    // Control: without the decoy the SHA-1 signature fails verification as rsa-sha256.
    expect(await verifyPostSignature(sp, sha1Signed, req)).toBe("bad");
    // Before the fix, the decoy made the verifier pick rsa-sha1 and accept.
    const decoyed = sha1Signed.replace(
      "<SignedInfo",
      '<x:SignatureMethod xmlns:x="urn:decoy" Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><SignedInfo',
    );
    expect(await verifyPostSignature(sp, decoyed, req)).toBe("bad");
  });
});
