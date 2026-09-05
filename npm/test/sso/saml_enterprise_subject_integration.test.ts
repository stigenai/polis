import * as forge from 'node-forge';
import * as jose from 'jose';
import saml from '@boxyhq/saml20';
import tap from 'tap';

import { JacksonError } from '../../src/controller/error';
import { enterpriseSubject } from '../../src/controller/enterprise-subject';
import type {
  IConnectionAPIController,
  IOAuthController,
  OAuthReq,
  OAuthTokenReq,
  SAMLResponsePayload,
  SAMLSSORecord,
} from '../../src/typings';
import { jacksonOptions } from '../utils';

const issuer = 'https://verified-idp.example/entity';
const identifierFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const tenant = 'verified-org';
const product = 'verified-product';
const redirectUrl = 'https://rp.example.test/callback';
const nameID = 'stable-subject@example.test';

const createCertificate = () => {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 3_600_000);
  const attributes = [{ name: 'commonName', value: 'Verified enterprise SAML test IdP' }];
  cert.setSubject(attributes);
  cert.setIssuer(attributes);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
    publicKey: forge.pki.certificateToPem(cert),
  };
};

const unsignedNameIDFormat = (xml: string, privateKey: string, publicKey: string) => {
  const unsigned = xml
    .replace(/<(?:\w+:)?Signature\b[\s\S]*?<\/(?:\w+:)?Signature>/g, '')
    .replace(/(<(?:\w+:)?NameID\b[^>]*?)\s+Format="[^"]*"([^>]*>)/, '$1$2');
  const assertionSigned = saml.sign(unsigned, privateKey, publicKey, '//*[local-name(.)="Assertion"]');
  return saml.sign(
    assertionSigned,
    privateKey,
    publicKey,
    '/*[local-name(.)="Response" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]'
  );
};

let enterpriseConnectionAPI: IConnectionAPIController;
let enterpriseOAuth: IOAuthController;
let legacyConnectionAPI: IConnectionAPIController;
let legacyOAuth: IOAuthController;
let enterpriseConnection: SAMLSSORecord;
let legacyConnection: SAMLSSORecord;
let closeEnterprise: () => Promise<void>;
let closeLegacy: () => Promise<void>;
let privateKey: string;
let publicKey: string;

tap.before(async () => {
  const originalSetInterval = global.setInterval;
  const originalSetTimeout = global.setTimeout;
  global.setInterval = ((...args: Parameters<typeof setInterval>) => {
    const timer = originalSetInterval(...args);
    timer.unref();
    return timer;
  }) as typeof setInterval;
  global.setTimeout = ((...args: Parameters<typeof setTimeout>) => {
    const timer = originalSetTimeout(...args);
    timer.unref();
    return timer;
  }) as typeof setTimeout;

  ({ privateKey, publicKey } = createCertificate());
  const signingKeys = await jose.generateKeyPair('RS256', { extractable: true });
  const jwtSigningKeys = {
    private: Buffer.from(await jose.exportPKCS8(signingKeys.privateKey)).toString('base64'),
    public: Buffer.from(await jose.exportSPKI(signingKeys.publicKey)).toString('base64'),
  };
  const rawMetadata = saml.createIdPMetadataXML({
    ssoUrl: 'https://verified-idp.example/sso',
    entityId: issuer,
    x509cert: publicKey,
    wantAuthnRequestsSigned: false,
  });
  const connection = {
    tenant,
    product,
    rawMetadata,
    defaultRedirectUrl: redirectUrl,
    redirectUrl: [redirectUrl],
    identifierFormat,
  };

  try {
    const enterprise = await (
      await import('../../src/index')
    ).default({
      ...jacksonOptions,
      openid: { ...jacksonOptions.openid, enterpriseSubjectV1: true, jwtSigningKeys },
    });
    enterpriseConnectionAPI = enterprise.connectionAPIController;
    enterpriseOAuth = enterprise.oauthController;
    closeEnterprise = enterprise.close;
    enterpriseConnection = await enterpriseConnectionAPI.createSAMLConnection(connection);

    const legacy = await (
      await import('../../src/index')
    ).default({
      ...jacksonOptions,
      openid: { ...jacksonOptions.openid, jwtSigningKeys },
    });
    legacyConnectionAPI = legacy.connectionAPIController;
    legacyOAuth = legacy.oauthController;
    closeLegacy = legacy.close;
    legacyConnection = await legacyConnectionAPI.createSAMLConnection(connection);
  } finally {
    global.setInterval = originalSetInterval;
    global.setTimeout = originalSetTimeout;
  }
});

tap.teardown(async () => {
  await enterpriseConnectionAPI.deleteConnections({ tenant, product });
  await legacyConnectionAPI.deleteConnections({ tenant, product });
  await closeEnterprise();
  await closeLegacy();
});

const completeSAMLCallback = async (
  oauth: IOAuthController,
  connection: SAMLSSORecord,
  options: { issuer?: string; withoutNameIDFormat?: boolean } = {}
) => {
  const authorization = (await oauth.authorize(<OAuthReq>{
    redirect_uri: redirectUrl,
    state: 'verified-state',
    client_id: `tenant=${tenant}&product=${product}`,
    scope: 'openid',
  })) as { redirect_url: string };
  const authorizeParams = new URL(authorization.redirect_url).searchParams;
  const relayState = authorizeParams.get('RelayState')!;
  const encodedRequest = authorizeParams.get('SAMLRequest')!;
  const requestXML = await saml.decodeBase64(encodedRequest, true);
  const requestID = requestXML.match(/\bID="([^"]+)"/)?.[1];
  if (!requestID) {
    throw new Error('Generated SAML request is missing its ID');
  }
  let responseXML = await saml.createSAMLResponse({
    audience: jacksonOptions.samlAudience!,
    issuer: options.issuer ?? issuer,
    acsUrl: `${jacksonOptions.externalUrl}${jacksonOptions.samlPath}`,
    claims: {
      email: nameID,
      raw: {
        email: nameID,
        displayName: 'Verified SAML User',
        verifiedSubjectNameID: 'attacker-controlled-attribute',
      },
    },
    requestId: requestID,
    privateKey,
    publicKey,
  });
  if (options.withoutNameIDFormat) {
    responseXML = unsignedNameIDFormat(responseXML, privateKey, publicKey);
  }
  const callback = await oauth.samlResponse(<SAMLResponsePayload>{
    SAMLResponse: Buffer.from(responseXML).toString('base64'),
    RelayState: relayState,
  });
  return new URL(callback.redirect_url!).searchParams;
};

const exchangeCode = async (oauth: IOAuthController, connection: SAMLSSORecord, code: string) => {
  const token = await oauth.token(<OAuthTokenReq>{
    grant_type: 'authorization_code',
    client_id: connection.clientID,
    client_secret: connection.clientSecret,
    code,
    redirect_uri: redirectUrl,
  });
  return oauth.userInfo(token.access_token);
};

tap.test('real signed SAML callback binds verified NameID provenance through userinfo', async (t) => {
  t.equal((enterpriseOAuth as any).opts.openid.enterpriseSubjectV1, true);
  const callback = await completeSAMLCallback(enterpriseOAuth, enterpriseConnection);
  const profile = await exchangeCode(enterpriseOAuth, enterpriseConnection, callback.get('code')!);
  const expectedSubject = enterpriseSubject([
    tenant,
    enterpriseConnection.clientID,
    issuer,
    identifierFormat,
    nameID,
  ]);

  t.equal(profile.sub, expectedSubject);
  t.same(profile.stigen_identity, {
    version: 1,
    protocol: 'saml',
    organization: tenant,
    connection: enterpriseConnection.clientID,
    upstreamIssuer: issuer,
    upstreamSubject: nameID,
    subjectFormat: identifierFormat,
    subject: expectedSubject,
  });
  t.equal(profile.raw.verifiedSubjectNameID, 'attacker-controlled-attribute');
});

tap.test('real signed SAML callback fails closed without verified NameID format', async (t) => {
  const callback = await completeSAMLCallback(enterpriseOAuth, enterpriseConnection, {
    withoutNameIDFormat: true,
  });
  t.equal(callback.get('error'), 'access_denied');
  t.notOk(callback.get('code'));
  t.match(callback.get('error_description'), /signed SAML NameID provenance/);
});

tap.test('real signed SAML callback rejects an unconfigured verified issuer', async (t) => {
  try {
    await completeSAMLCallback(enterpriseOAuth, enterpriseConnection, {
      issuer: 'https://other-idp.example/entity',
    });
    t.fail('Expected the callback to reject an unconfigured issuer');
  } catch (error) {
    if (!(error instanceof JacksonError)) {
      t.fail('Expected a JacksonError for an unconfigured issuer');
      return;
    }
    t.equal(error.statusCode, 403);
    t.equal(error.internalError, 'SAML connection not found.');
  }
});

tap.test('legacy signed SAML callback keeps the historical subject', async (t) => {
  const callback = await completeSAMLCallback(legacyOAuth, legacyConnection);
  const profile = await exchangeCode(legacyOAuth, legacyConnection, callback.get('code')!);
  t.equal(profile.sub, nameID);
  t.notOk(profile.stigen_identity);
});
