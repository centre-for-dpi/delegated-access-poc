# BirthCertificate

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
  "type": [
    "VerifiableCredential",
    "BirthCertificate"
  ],
  "issuer": {
    "id": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
    "name": "Testa Gava Civil Registry"
  },
  "issuanceDate": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
  "credentialSubject": {
    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "fullName": "Maria Garcia Lopez",
    "firstName": "Maria",
    "lastName": "Garcia Lopez",
    "dateOfBirth": "2015-03-10",
    "sex": "F",
    "placeOfBirth": {
      "country": "Peru",
      "city": "Lima"
    },
    "nationality": "PER",
    "documentNumber": "12345678",
    "registrationNumber": "REG-2015-00042",
    "dateOfRegistration": "2015-03-15"
  },
  "credentialStatus": {
    "type": "BitstringStatusListEntry",
    "statusListCredential": "http://status-list-service:7006/status/revocation/1",
    "statusListIndex": "0",
    "statusPurpose": "revocation"
  }
}
```

## Manifest

```json
{
  "claims": {
    "Document Number": "$.credentialSubject.documentNumber",
    "Registration Number": "$.credentialSubject.registrationNumber",
    "First Name": "$.credentialSubject.firstName",
    "Last Name": "$.credentialSubject.lastName",
    "Full Name": "$.credentialSubject.fullName",
    "Date of Birth": "$.credentialSubject.dateOfBirth",
    "Sex": "$.credentialSubject.sex",
    "Nationality": "$.credentialSubject.nationality",
    "Place of Birth Country": "$.credentialSubject.placeOfBirth.country",
    "Place of Birth City": "$.credentialSubject.placeOfBirth.city",
    "Date of Registration": "$.credentialSubject.dateOfRegistration"
  }
}
```

## Mapping example

```json
{
  "id": "<uuid>",
  "issuer": {
    "id": "<issuerDid>"
  },
  "issuanceDate": "<timestamp>"
}
```
