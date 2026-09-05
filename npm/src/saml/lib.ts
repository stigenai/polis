import crypto from 'crypto';
import saml from '@boxyhq/saml20';
import type { SAMLProfile } from '@boxyhq/saml20/dist/typings';
import * as dbutils from '../db/utils';
import type { VerifiedUpstreamIdentity } from '../typings';
import claims from '../saml/claims';

type ValidatedSAMLProfile = SAMLProfile & {
  verifiedIdentity?: VerifiedUpstreamIdentity;
};

// Validate the SAMLResponse and extract the user profile
export const extractSAMLResponseAttributes = async (
  decodedResponse: string,
  validateOpts: ValidateOption
) => {
  const attributes: ValidatedSAMLProfile = await saml.validate(decodedResponse, validateOpts);

  if (attributes && attributes.claims) {
    delete attributes.verifiedIdentity;
    const verifiedNameID = attributes.verifiedSubjectNameID;
    if (verifiedNameID) {
      attributes.verifiedIdentity = {
        protocol: 'saml',
        issuer: attributes.issuer,
        subject: verifiedNameID.value,
        subjectFormat: verifiedNameID.format,
      };
    }

    // We map claims to our attributes id, email, firstName, lastName where possible. We also map original claims to raw
    attributes.claims = claims.map(attributes.claims);

    // Some providers don't return the id in the assertion, we set it to a sha256 hash of the email
    if (!attributes.claims.id && attributes.claims.email) {
      attributes.claims.id = crypto.createHash('sha256').update(attributes.claims.email).digest('hex');
    }

    if (!attributes.claims.id) {
      throw new Error(
        'SAML assertion is missing both id (NameID) and email. Ensure the IdP is configured to send at least one of these attributes.'
      );
    }
  }

  // we'll send a ripemd160 hash of the id, this can be used in the case of email missing it can be used as the local part
  attributes.claims.idHash = dbutils.keyDigest(attributes.claims.id);

  return attributes;
};

export type ValidateOption = {
  thumbprint?: string;
  publicKey?: string;
  audience: string;
  privateKey: string;
  inResponseTo?: string;
};
