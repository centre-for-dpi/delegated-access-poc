# ParentalDelegationCredential

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "id": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
  "type": [
    "VerifiableCredential",
    "ParentalDelegationCredential"
  ],
  "issuer": {
    "id": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
    "name": "Testa Gava Civil Registry"
  },
  "issuanceDate": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
  "expirationDate": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
  "credentialSubject": {
    "id": "THIS WILL BE REPLACED WITH DYNAMIC DATA FUNCTION",
    "fullName": "Ana Lopez Martinez",
    "firstName": "Ana",
    "lastName": "Lopez Martinez",
    "documentNumber": "87654321",
    "role": "Mother",
    "onBehalfOf": {
      "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      "fullName": "Maria Garcia Lopez",
      "documentNumber": "12345678",
      "dateOfBirth": "2015-03-10"
    }
  },
  "credentialStatus": {
    "type": "BitstringStatusListEntry",
    "statusListCredential": "http://status-list-service:7006/status/revocation/1",
    "statusListIndex": "1",
    "statusPurpose": "revocation"
  }
}
```

## Manifest

```json
{
  "claims": {
    "Delegate Document Number": "$.credentialSubject.documentNumber",
    "Delegate First Name": "$.credentialSubject.firstName",
    "Delegate Last Name": "$.credentialSubject.lastName",
    "Delegate Full Name": "$.credentialSubject.fullName",
    "Role": "$.credentialSubject.role",
    "Child ID": "$.credentialSubject.onBehalfOf.id",
    "Child Full Name": "$.credentialSubject.onBehalfOf.fullName",
    "Child Document Number": "$.credentialSubject.onBehalfOf.documentNumber",
    "Child Date of Birth": "$.credentialSubject.onBehalfOf.dateOfBirth"
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
  "credentialSubject": {
    "id": "<subjectDid>"
  },
  "issuanceDate": "<timestamp>",
  "expirationDate": "<timestamp-in:6570d>"
}
```

<!--
**Note: The `expirationDate` mapping uses `<timestamp-in:6570d>` (approximately 18 years) as a placeholder. In production, this should be calculated dynamically based on the child's date of birth and the jurisdiction's legal age of majority.
-->
