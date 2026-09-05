import tap from 'tap';
import { buildEnterpriseIdentity } from '../../src/controller/enterprise-subject';
import type { SAMLSSORecord } from '../../src/typings';

tap.test('SAML verified provenance exactly matches configured issuer and format', (t) => {
  const issuer = 'https://idp.example/entity';
  const format = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
  const connection = {
    tenant: 'org-a',
    clientID: 'connection-a',
    identifierFormat: format,
    idpMetadata: { entityID: issuer },
  } as SAMLSSORecord;
  const verifiedIdentity = {
    protocol: 'saml',
    issuer,
    subject: 'stable-subject',
    subjectFormat: format,
  };

  t.equal(buildEnterpriseIdentity(connection, { verifiedIdentity }).upstreamSubject, 'stable-subject');
  for (const overrides of [
    { issuer: 'https://other-idp.example/entity' },
    { issuer: `${issuer}/` },
    { subjectFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' },
  ]) {
    t.throws(
      () =>
        buildEnterpriseIdentity(connection, {
          verifiedIdentity: { ...verifiedIdentity, ...overrides },
        }),
      /Enterprise identity SAML provenance does not match the resolved connection/
    );
  }
  t.end();
});
