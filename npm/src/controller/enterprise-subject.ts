import crypto from 'crypto';

import type { OIDCSSORecord, SAMLSSORecord } from '../typings';

const samlNameIdentifierClaim = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';
export type EnterpriseIdentity = {
  version: 1;
  protocol: 'oidc' | 'saml';
  organization: string;
  connection: string;
  upstreamIssuer: string;
  upstreamSubject: string;
  subjectFormat?: string;
  subject: string;
};

function required(name: string, value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value !== value.trim()) {
    throw new Error(`Missing or invalid enterprise identity ${name}`);
  }
  return value;
}

// Length framing makes the digest input unambiguous without modifying any value.
// In particular, issuer strings are not URL-normalized: the exact issuer already
// validated by the protocol library is part of the identity key.
export function enterpriseSubject(parts: readonly string[]): string {
  const hash = crypto.createHash('sha256');
  hash.update('stigen-enterprise-subject\x00v1\x00');
  for (const part of parts) {
    const value = Buffer.from(part, 'utf8');
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(value.length);
    hash.update(length);
    hash.update(value);
  }
  return `stigen-enterprise-v1.${hash.digest('base64url')}`;
}

export function buildEnterpriseIdentity(
  connection: SAMLSSORecord | OIDCSSORecord,
  profile: any
): EnterpriseIdentity {
  const organization = required('organization', connection.tenant);
  const connectionID = required('connection', connection.clientID);

  if ('oidcProvider' in connection) {
    const raw = profile?.claims?.raw;
    const upstreamIssuer = required('OIDC issuer', raw?.iss);
    const upstreamSubject = required('OIDC subject', raw?.sub);
    return {
      version: 1,
      protocol: 'oidc',
      organization,
      connection: connectionID,
      upstreamIssuer,
      upstreamSubject,
      subject: enterpriseSubject([organization, connectionID, upstreamIssuer, upstreamSubject]),
    };
  }

  const raw = profile?.claims?.raw;
  // Only a NameID/explicit id from the validated assertion is accepted. Polis's
  // legacy sha256(email) fallback is intentionally excluded.
  const nameID = raw?.id ?? raw?.[samlNameIdentifierClaim];
  const upstreamSubject = required('SAML NameID', nameID);
  const upstreamIssuer = required('SAML issuer', profile?.issuer);
  const configuredIssuer = required('configured SAML issuer', connection.idpMetadata.entityID);
  if (upstreamIssuer !== configuredIssuer) {
    throw new Error('Enterprise identity SAML issuer does not match the resolved connection');
  }
  // The current saml20 profile does not return the assertion's Format attribute.
  // Require the explicit server-side connection format rather than silently
  // applying Polis's legacy emailAddress default.
  const subjectFormat = required('SAML NameID format', connection.identifierFormat);
  return {
    version: 1,
    protocol: 'saml',
    organization,
    connection: connectionID,
    upstreamIssuer,
    upstreamSubject,
    subjectFormat,
    subject: enterpriseSubject([organization, connectionID, upstreamIssuer, subjectFormat, upstreamSubject]),
  };
}
