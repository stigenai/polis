import crypto from 'crypto';

import type { OIDCSSORecord, SAMLSSORecord } from '../typings';

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
    const verified = profile?.verifiedIdentity;
    if (verified?.protocol !== 'oidc') {
      throw new Error('Missing or invalid enterprise identity OIDC provenance');
    }
    const upstreamIssuer = required('OIDC issuer', verified.issuer);
    const upstreamSubject = required('OIDC subject', verified.subject);
    const configuredIssuer = required('configured OIDC issuer', verified.configuredIssuer);
    const resolvedIssuer = configuredIssuer.includes('{tenantid}')
      ? configuredIssuer.replace('{tenantid}', required('OIDC issuer tenant id', verified.issuerTenantID))
      : configuredIssuer;
    if (upstreamIssuer !== resolvedIssuer) {
      throw new Error('Enterprise identity OIDC issuer does not match the resolved connection');
    }
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

  // saml20 currently returns a validated issuer and mapped NameID value, but not
  // the signed assertion's actual NameID Format. A configured/requested format is
  // not response evidence. Fail closed until the validator exposes a typed
  // verifiedIdentity envelope equivalent to the OIDC path.
  const verified = profile?.verifiedIdentity;
  if (verified?.protocol !== 'saml') {
    throw new Error('Missing or invalid enterprise identity signed SAML NameID provenance');
  }
  const upstreamSubject = required('SAML NameID', verified.subject);
  const upstreamIssuer = required('SAML issuer', verified.issuer);
  const subjectFormat = required('SAML NameID format', verified.subjectFormat);
  const configuredIssuer = required('configured SAML issuer', connection.idpMetadata.entityID);
  const configuredFormat = required('configured SAML NameID format', connection.identifierFormat);
  if (upstreamIssuer !== configuredIssuer || subjectFormat !== configuredFormat) {
    throw new Error('Enterprise identity SAML provenance does not match the resolved connection');
  }
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
