// A throwaway RS256 keypair, generated solely for the test suite.
//
// Yes, a private key is committed here, and that is deliberate: tests that
// assert an id_token verifies against /jwks.json need both halves, and a key
// generated at test time cannot be in a static Worker config. It signs nothing
// but test fixtures. The public half is in wrangler.test.jsonc; if you rotate
// one, rotate both.
//
// Generated with:
//   node -e "const {generateKeyPairSync}=require('node:crypto'); \
//     const {publicKey,privateKey}=generateKeyPairSync('rsa',{modulusLength:2048}); \
//     console.log(privateKey.export({type:'pkcs8',format:'pem'})); \
//     console.log(JSON.stringify(publicKey.export({format:'jwk'})))"

export const TEST_SIGNING_KEY_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCQa1NEjuDJ6Xoq
LNfe+88vBe9GPjg8ja/py96dIZ1+H8Ol4Rnu3VTqWLUSuS93kcuXa4hBttSQRWX9
lt2m4S9bO1E8+7/2w69RGwhDtWMO41B2UqJXaF0t6ecmrSZelTXwXFuy5aCPI3TF
weKZnvQMlWGKW7llc4zcIBUAHllQ6caT7LGBuHIP0UTXUFzPiE4eSwQK1ukmtg+v
l8AJoSdApdE9QKYgVUGglbn5pOsxJs0bwrMH8vp/d843V5gVx7o6M2+XGai1O+Q8
JAp/yi8hxgYvBBKSbKJuRABRavpXFSvlaJFqgFVInbpYVawKkCNbduqjyXjdlmQ9
f2NbR/xhAgMBAAECggEAArPPbL1TstOInVjAzVkJk8gDpd0s2403LnkfIvI/FTNu
S3X+hea5sQzp49N38j/V1HExrTEeTHjP+MJ68VAjZ7dLb4hdG4v72tkA+uteUtKp
bcgMEPX7UGGhGVXXcvZNz7/wA1VNVNWwA1ymay4l7kUD/JJ3fKYrNkSaFVTRYl8w
9iIhNag/WwQjQxG/m6auIk1Hb2REU+z9b04f9UdFZbE1VT1JwMrDPu9JFTOZTXd3
CZGZoJ9WbJzI8DzjeqJ/PghM27UH1wb5yMlbDFnPTlIrw4LgsH0P2b91nGnPW3wj
xerZPLK/N2R9I8WtUDCK/Dy8rYb286Ffk6n4Ak6FlQKBgQDJqpx/rKOfAPbo2vrm
u7/Px2j7FCn4+V7PZnNdnBB+YDeD7h4gjg0lieNTF2WWQpHn5t7eNsh6KVvwnLMd
aqk+ip8osCfH6TTG3WaJd9ylGzeBjQUxrX3TDuBAjSmSWmpRa/BijqVch3V1IJxX
2yoT674wqHkKGcUM7EFLj8NDvwKBgQC3VD66H18Ra4FxPDW6iMN1b7U1Sa6Y4N8B
Cq2MpqVTBHz6noo0JClYezRhogSi/d56zjCceh+i7htDeHF2qZfdEAx4uQriPwTt
aBrZz99qaDkNFYKy0p1TadUG1q1PORoQh4jrqmJmdaaGJ55hyCp1s43zMbvo5mcc
yhDcqRpH3wKBgQCjZWUf3VVFQ5bK3IJl6MFlLIDWzmOjowk6qhvXQNfsTTEt6ATp
A6+LNsnFTTO2J4Hoj5sMGP8eW9xue8h0kTNHxTFn2jKhO0bTyheGUmOoMwEqKoSG
17cXBvqT0sxYFIIILpi6gjFhYy+8EwwZ8y2Irn2PFzHbCT4rVlEhU/42KQKBgHPa
ChXGU2aHwHIVcYKigJpK8IFvQaWcnXBkFg5HFTykHnKmE4Ilw/cFTLHSGAoEUj7a
4/9OcYWd4J6/kzxAqhZp2OfFT+pvlqaMXkN8yJvOpxbsm/5zeDZJL/S1XyosVJtT
eyQqNSq4eHZYvQ7f1m0w/ahMqongaBLaYtN/DXuTAoGAQlZyXCbK07uqsj15BdKT
bXvu8cJIIYNRGkttz1xF8PJYDFW6uSLBUp1etCyBZP7K/w4uIohlIlosYNDsrQFu
rtzzzUHED6RU/GmO204OKMpXrFN32u0Oc0p9bQsRMTOC8Q0BCyWpJ9pqHDKO43rO
NOhGeKaim+Dzr/e9H00PxAU=
-----END PRIVATE KEY-----
`;
