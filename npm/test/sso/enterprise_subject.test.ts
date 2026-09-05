import tap from 'tap';

import { buildEnterpriseIdentity } from '../../src/controller/enterprise-subject';
import { createOIDCUserProfile } from '../../src/controller/utils';
import type { OIDCSSORecord, SAMLSSORecord } from '../../src/typings';

const oidcConnection = (overrides: Partial<OIDCSSORecord> = {}): OIDCSSORecord =>
  ({
    tenant: 'org-a',
    product: 'infra-blocks',
    clientID: 'connection-a',
    clientSecret: 'not-used',
    defaultRedirectUrl: 'https://rp.example/callback',
    redirectUrl: ['https://rp.example/callback'],
    oidcProvider: { provider: 'Unknown', friendlyProviderName: null },
    ...overrides,
  }) as OIDCSSORecord;

const oidcProfile = (issuer = 'https://issuer.example', subject = 'subject-123') => ({
  verifiedIdentity: { protocol: 'oidc', issuer, subject, configuredIssuer: issuer },
  claims: { raw: { iss: issuer, sub: subject, email: 'shared@example.com' } },
});

const samlConnection = (overrides: Partial<SAMLSSORecord> = {}): SAMLSSORecord =>
  ({
    tenant: 'org-a',
    product: 'infra-blocks',
    clientID: 'connection-a',
    clientSecret: 'not-used',
    defaultRedirectUrl: 'https://rp.example/callback',
    redirectUrl: ['https://rp.example/callback'],
    identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    idpMetadata: {
      entityID: 'https://saml-idp.example/entity',
      provider: 'Unknown',
      friendlyProviderName: null,
      slo: {},
      sso: {},
    },
    ...overrides,
  }) as SAMLSSORecord;

const samlProfile = (issuer = 'https://saml-idp.example/entity', nameID = 'subject-123') => ({
  issuer,
  verifiedIdentity: {
    protocol: 'saml',
    issuer,
    subject: nameID,
    subjectFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  },
  claims: {
    id: nameID,
    email: 'shared@example.com',
    raw: { 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier': nameID },
  },
});

tap.test('OIDC enterprise subjects bind exact trusted provenance', (t) => {
  const base = buildEnterpriseIdentity(oidcConnection(), oidcProfile());
  t.equal(base.upstreamIssuer, 'https://issuer.example');
  t.equal(base.upstreamSubject, 'subject-123');

  const variants = [
    buildEnterpriseIdentity(oidcConnection({ tenant: 'org-b' }), oidcProfile()),
    buildEnterpriseIdentity(oidcConnection({ clientID: 'connection-b' }), oidcProfile()),
    buildEnterpriseIdentity(oidcConnection(), oidcProfile('https://other-issuer.example')),
    buildEnterpriseIdentity(oidcConnection(), oidcProfile('https://issuer.example/')),
    buildEnterpriseIdentity(oidcConnection(), oidcProfile('https://issuer.example', 'subject-456')),
  ];
  for (const variant of variants) {
    t.not(variant.subject, base.subject);
  }
  t.end();
});

tap.test('userinfo cannot overwrite validated OIDC provenance', (t) => {
  const profile = createOIDCUserProfile(
    { iss: 'https://issuer.example', sub: 'validated-subject', email: 'validated@example.com' },
    { iss: 'https://attacker.example', sub: 'attacker-subject', email: 'profile@example.com' },
    'https://issuer.example'
  );
  t.same(profile.verifiedIdentity, {
    protocol: 'oidc',
    issuer: 'https://issuer.example',
    subject: 'validated-subject',
    configuredIssuer: 'https://issuer.example',
    issuerTenantID: undefined,
  });
  // Raw remains backwards-compatible profile material and demonstrates why it
  // is not an authentication provenance source.
  t.equal(profile.claims.raw?.iss, 'https://attacker.example');
  t.equal(profile.claims.raw?.sub, 'attacker-subject');

  const identity = buildEnterpriseIdentity(oidcConnection(), profile);
  t.equal(identity.upstreamIssuer, 'https://issuer.example');
  t.equal(identity.upstreamSubject, 'validated-subject');
  t.throws(
    () =>
      buildEnterpriseIdentity(
        oidcConnection(),
        createOIDCUserProfile(
          { iss: 'https://issuer.example/', sub: 'validated-subject' },
          {},
          'https://issuer.example'
        )
      ),
    /does not match/
  );
  t.end();
});

tap.test('OIDC issuer templates resolve exactly as validated provider metadata', (t) => {
  const tenantID = '11111111-2222-3333-4444-555555555555';
  const profile = createOIDCUserProfile(
    {
      iss: `https://login.microsoftonline.com/${tenantID}/v2.0`,
      sub: 'entra-subject',
      tid: tenantID,
    },
    {},
    'https://login.microsoftonline.com/{tenantid}/v2.0'
  );
  t.match(buildEnterpriseIdentity(oidcConnection(), profile).subject, /^stigen-enterprise-v1\./);
  t.throws(
    () =>
      buildEnterpriseIdentity(oidcConnection(), {
        ...profile,
        verifiedIdentity: { ...profile.verifiedIdentity, issuerTenantID: 'different-tenant' },
      }),
    /does not match/
  );
  t.end();
});

tap.test('SAML enterprise subjects bind issuer, NameID, and configured format', (t) => {
  const base = buildEnterpriseIdentity(samlConnection(), samlProfile());
  const variants = [
    buildEnterpriseIdentity(samlConnection({ tenant: 'org-b' }), samlProfile()),
    buildEnterpriseIdentity(samlConnection({ clientID: 'connection-b' }), samlProfile()),
    buildEnterpriseIdentity(
      samlConnection({
        idpMetadata: {
          ...samlConnection().idpMetadata,
          entityID: 'https://other-idp.example/entity',
        },
      }),
      samlProfile('https://other-idp.example/entity')
    ),
    buildEnterpriseIdentity(
      samlConnection({ identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' }),
      {
        ...samlProfile(),
        verifiedIdentity: {
          ...samlProfile().verifiedIdentity,
          subjectFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        },
      }
    ),
    buildEnterpriseIdentity(samlConnection(), samlProfile(undefined, 'subject-456')),
  ];
  for (const variant of variants) {
    t.not(variant.subject, base.subject);
  }
  t.end();
});

tap.test('enterprise subject construction fails closed on missing provenance', (t) => {
  const cases: Array<() => unknown> = [
    () => buildEnterpriseIdentity(oidcConnection({ tenant: '' }), oidcProfile()),
    () => buildEnterpriseIdentity(oidcConnection({ clientID: '' }), oidcProfile()),
    () =>
      buildEnterpriseIdentity(oidcConnection(), {
        claims: { raw: { iss: 'https://issuer.example', sub: 'subject-123' } },
      }),
    () => buildEnterpriseIdentity(oidcConnection(), oidcProfile('', 'subject-123')),
    () => buildEnterpriseIdentity(oidcConnection(), oidcProfile('https://issuer.example', '')),
    () =>
      buildEnterpriseIdentity(oidcConnection(), {
        ...oidcProfile(),
        verifiedIdentity: { ...oidcProfile().verifiedIdentity, configuredIssuer: '' },
      }),
    () => buildEnterpriseIdentity(samlConnection(), { issuer: '', claims: { raw: { id: 'name-id' } } }),
    () => buildEnterpriseIdentity(samlConnection(), { issuer: 'https://idp.example', claims: { raw: {} } }),
    () => buildEnterpriseIdentity(samlConnection(), { ...samlProfile(), verifiedIdentity: undefined }),
    () =>
      buildEnterpriseIdentity(samlConnection(), {
        ...samlProfile(),
        verifiedIdentity: { ...samlProfile().verifiedIdentity, subjectFormat: '' },
      }),
  ];
  for (const run of cases) {
    t.throws(run, /(Missing or invalid enterprise identity|does not match the resolved connection)/);
  }
  t.end();
});

tap.test('email is never an enterprise subject input', (t) => {
  const first = buildEnterpriseIdentity(oidcConnection(), oidcProfile());
  const changedEmail = oidcProfile();
  changedEmail.claims.raw.email = 'renamed@example.com';
  const second = buildEnterpriseIdentity(oidcConnection(), changedEmail);
  t.equal(second.subject, first.subject);

  // A SAML assertion without a NameID/explicit id is rejected even when email
  // is present, preventing the legacy sha256(email) fallback from becoming a
  // federated credential key.
  t.throws(
    () =>
      buildEnterpriseIdentity(samlConnection(), {
        issuer: 'https://saml-idp.example/entity',
        claims: {
          id: 'legacy-email-hash',
          email: 'shared@example.com',
          raw: { email: 'shared@example.com' },
        },
      }),
    /SAML NameID/
  );
  t.end();
});
