// didweb_vp_demo_sdr.js
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import express from 'express';
import { fileURLToPath } from 'url';

import { Resolver } from 'did-resolver';
import { getResolver as getWebDidResolver } from 'web-did-resolver';
import { createAgent } from '@veramo/core';
import { DIDManager } from '@veramo/did-manager';
import { KeyDIDProvider, getDidKeyResolver } from '@veramo/did-provider-key';
import { KeyManager } from '@veramo/key-manager';
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { CredentialPlugin } from '@veramo/credential-w3c';
import { Entities, KeyStore, DIDStore, PrivateKeyStore, migrations } from '@veramo/data-store';
import { DataSource } from 'typeorm';

// Helper __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Base roots (avoid OneDrive weirdness on Windows)
const PREFERRED_WINDOWS_ROOT = 'C:/public-demo';
const useWindowsRoot = process.platform === 'win32' && fs.existsSync(path.parse(process.cwd()).root);
const BASE_PUBLIC_ROOT = useWindowsRoot ? PREFERRED_WINDOWS_ROOT : path.resolve(process.cwd(), 'public-demo');
const BASE_DATA_ROOT = useWindowsRoot ? 'C:/data-veramo' : path.resolve(process.cwd(), 'data-veramo');

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
}

function normalizeForExpress(p) {
  return path.resolve(p).replace(/\\/g, '/');
}

function randomHex32() {
  return crypto.randomBytes(32).toString('hex');
}

// create TypeORM DB
async function createAgentDB(dbFile) {
  ensureDir(path.dirname(dbFile));
  const ds = new DataSource({
    type: 'sqlite',
    database: dbFile,
    synchronize: true,
    migrations,
    entities: Entities,
  });
  await ds.initialize();
  return ds;
}

function createAgentUsingDB(db, secretHex) {
  const resolvers = {
    ...getDidKeyResolver(),
    ...getWebDidResolver(),
  };

  return createAgent({
    plugins: [
      new KeyManager({
        store: new KeyStore(db),
        kms: {
          local: new KeyManagementSystem(new PrivateKeyStore(db, new SecretBox(secretHex))),
        },
      }),
      new DIDManager({
        store: new DIDStore(db),
        defaultProvider: 'did:key',
        providers: { 'did:key': new KeyDIDProvider({ defaultKms: 'local' }) },
      }),
      new DIDResolverPlugin({ resolver: new Resolver(resolvers) }),
      new CredentialPlugin(),
    ],
  });
}

function saveJson(filePath, obj) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), 'utf8');
  console.log('Saved:', filePath);
}

function writeDidWebDoc(publicDir, didWebId, controllerDid, publicJwk, serviceEntries = []) {
  const doc = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: didWebId,
    verificationMethod: [
      {
        id: `${controllerDid}#keys-1`,
        type: 'JsonWebKey2020',
        controller: controllerDid,
        publicKeyJwk: publicJwk,
      },
    ],
    assertionMethod: [`${controllerDid}#keys-1`],
  };
  if (serviceEntries && serviceEntries.length) doc.service = serviceEntries;
  const wellKnown = path.join(publicDir, '.well-known');
  ensureDir(wellKnown);
  saveJson(path.join(wellKnown, 'did.json'), doc);
  return doc;
}

// Start HTTP server exposing only .well-known and /vp (do NOT expose /vc)
function startAgentServer(publicDir, port) {
  ensureDir(publicDir);
  ensureDir(path.join(publicDir, '.well-known'));
  ensureDir(path.join(publicDir, 'vp'));

  const app = express();
  app.use('/.well-known', express.static(path.join(publicDir, '.well-known')));
  app.use('/vp', express.static(path.join(publicDir, 'vp')));

  app.get('/__info', (req, res) => {
    res.json({
      publicDir: normalizeForExpress(publicDir),
      wellKnown: fs.existsSync(path.join(publicDir, '.well-known')) ? fs.readdirSync(path.join(publicDir, '.well-known')) : [],
      vp: fs.existsSync(path.join(publicDir, 'vp')) ? fs.readdirSync(path.join(publicDir, 'vp')) : [],
    });
  });

  const server = app.listen(port, () => {
    console.log(`[HTTP] Serving ${normalizeForExpress(publicDir)} at http://localhost:${port}/ (/.well-known + /vp)`);
  });
  return server;
}

/**
 * Helper: filter a credential's credentialSubject to only allowed fields
 * (keeps id always, and any allowed keys)
 */
function redactCredentialForSdr(vc, allowedFields = ['name', 'skills']) {
  // vc may be JWT string or object. If jwt string, we cannot inspect content
  // but in this demo we store full objects (since createVerifiableCredential returns object)
  const copy = JSON.parse(JSON.stringify(vc)); // deep copy
  if (!copy.credentialSubject && copy.credential && copy.credential.credentialSubject) {
    // some veramo forms keep properties under credential
    copy.credentialSubject = copy.credential.credentialSubject;
  }
  const subj = copy.credentialSubject || (copy.credential && copy.credential.credentialSubject) || {};
  const filtered = { id: subj.id };
  for (const k of allowedFields) {
    if (subj[k] !== undefined) filtered[k] = subj[k];
  }
  // place filtered subject in the same shape as original
  if (copy.credentialSubject) {
    copy.credentialSubject = filtered;
  } else if (copy.credential && copy.credential.credentialSubject) {
    copy.credential.credentialSubject = filtered;
  } else {
    // fallback
    copy.credentialSubject = filtered;
  }
  return copy;
}

async function main() {
  console.log('Base public root:', BASE_PUBLIC_ROOT);
  console.log('Base data root:', BASE_DATA_ROOT);
  ensureDir(BASE_PUBLIC_ROOT);
  ensureDir(BASE_DATA_ROOT);

  const AGENTS = [
    { name: 'infobel', port: 3030 },
    { name: 'alice', port: 3031 },
    { name: 'bob', port: 3032 },
    { name: 'charlie', port: 3033 },
    { name: 'amd', port: 3034 },
    { name: 'ibm', port: 3035 },
  ];

  const infos = {};

  // Create agents
  for (const a of AGENTS) {
    const publicDir = path.join(BASE_PUBLIC_ROOT, a.name);
    const dbFile = path.join(BASE_DATA_ROOT, `${a.name}.sqlite`);
    const secret = randomHex32();

    ensureDir(publicDir);
    ensureDir(path.join(publicDir, '.well-known'));
    ensureDir(path.join(publicDir, 'vp'));

    const db = await createAgentDB(dbFile);
    const agent = createAgentUsingDB(db, secret);
    const server = startAgentServer(publicDir, a.port);

    const created = await agent.didManagerCreate();
    const keyEntry = created.keys && created.keys[0];
    const publicKeyHex = keyEntry?.publicKeyHex || null;
    const publicJwk = publicKeyHex ? { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(publicKeyHex, 'hex').toString('base64url') } : { kty: 'unknown' };

    // attach app/device info (useful for audience alignment)
    agent.deviceInfo = { appName: a.name, appUrl: `http://localhost:${a.port}` };

    infos[a.name] = {
      name: a.name,
      port: a.port,
      publicDir,
      db,
      secret,
      agent,
      server,
      identifier: created,
      publicJwk,
      didWeb: null,
      deviceInfo: agent.deviceInfo,
    };

    console.log(`Agent ${a.name} created did:key: ${created.did}`);
    console.log(`  publicDir (disk): ${publicDir}`);
    console.log(`  DB file         : ${dbFile}`);
    console.log(' appurl:', `http://localhost:${a.port}`, ' appname:', a.name);
  }

  // publish did:web documents (point at did:key controller)
  console.log('\n=== Publishing did.web documents ===');
  for (const name in infos) {
    const info = infos[name];
    const didWeb = `did:web:localhost:${info.port}`;
    info.didWeb = didWeb;
    writeDidWebDoc(info.publicDir, didWeb, info.identifier.did, info.publicJwk, []);
    console.log(`  ${name} → ${didWeb} (http://localhost:${info.port}/.well-known/did.json)`);
  }

  // Registration: Alice/Bob/Charlie register with Infobel
  console.log('\n=== Registration: Alice, Bob, Charlie register with Infobel ===');
  const infobel = infos['infobel'];
  const developersDirectory = ['alice', 'bob', 'charlie'].map((dev) => ({
    id: infos[dev].didWeb,
    name: dev,
    // NOTE: we will NOT expose these VCs; these endpoints are illustrative only.
    vcEndpoint: `http://localhost:${infobel.port}/vc/${dev}.json`,
  }));
  const visitors = [{ id: infos['amd'].didWeb, name: 'AMD' }, { id: infos['ibm'].didWeb, name: 'IBM' }];

  const infobelDidPath = path.join(infobel.publicDir, '.well-known', 'did.json');
  let infobelDidDoc = {};
  try {
    infobelDidDoc = JSON.parse(fs.readFileSync(infobelDidPath, 'utf8'));
  } catch (e) {
    infobelDidDoc = { id: infobel.didWeb };
  }
  infobelDidDoc.service = [
    { id: `${infobel.didWeb}#developer-directory`, type: 'DeveloperDirectory', entries: developersDirectory },
    { id: `${infobel.didWeb}#visitors`, type: 'RegisteredVisitors', entries: visitors },
  ];
  saveJson(infobelDidPath, infobelDidDoc);
  console.log('Infobel did.json updated with directory + visitors.');

  // Infobel issues VCs — PRIVATE (we'll store them under data-veramo and NOT serve them)
  console.log('\n=== Infobel issues private VCs for developers (aud -> AMD+IBM) ===');

  // audience: use did:web identifiers for AMD and IBM (Veramo expects aud)
  const audience = [infos['amd'].didWeb, infos['ibm'].didWeb];

  // We'll include private field homeAddress in VC credentialSubject but keep VC files private on disk.
  async function issueVC(issuerAgent, issuerManagedDid, holderDid, holderName, skills, homeAddress) {
    // create the full credential subject
    const credential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential', 'DeveloperCredential'],
      issuer: { id: issuerManagedDid },
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: holderDid,
        name: holderName,
        skills,
        homeAddress, // private
      },
      // add aud to the JWT so the audience check passes at verification
      aud: audience,
    };

    return issuerAgent.createVerifiableCredential({
      credential,
      proofFormat: 'jwt',
    });
  }

  const issuerManagedDid = infobel.identifier.did;

  // Example developer data
  const devData = {
    alice: { skills: ['js', 'node', 'veramo'], homeAddress: '1 Alice St, Secretville' },
    bob: { skills: ['go', 'k8s'], homeAddress: '2 Bob Rd, Hidden City' },
    charlie: { skills: ['rust', 'security'], homeAddress: '3 Charlie Ave, Privateburg' },
  };

  const aliceVC = await issueVC(infobel.agent, issuerManagedDid, infos['alice'].didWeb, 'Alice', devData.alice.skills, devData.alice.homeAddress);
  const bobVC = await issueVC(infobel.agent, issuerManagedDid, infos['bob'].didWeb, 'Bob', devData.bob.skills, devData.bob.homeAddress);
  const charlieVC = await issueVC(infobel.agent, issuerManagedDid, infos['charlie'].didWeb, 'Charlie', devData.charlie.skills, devData.charlie.homeAddress);

  // Store VCs privately on disk (NOT served by the Express static server)
  const privateVcDir = path.join(BASE_DATA_ROOT, 'infobel-vcs');
  ensureDir(privateVcDir);
  saveJson(path.join(privateVcDir, 'alice.json'), aliceVC);
  saveJson(path.join(privateVcDir, 'bob.json'), bobVC);
  saveJson(path.join(privateVcDir, 'charlie.json'), charlieVC);
  console.log('Infobel issued VCs (stored privately):', privateVcDir);

  // Combined VP: embed the full VCs (this VP is public so AMD/IBM can fetch it) - audience MUST match verifiers
  console.log('\n=== Infobel creates combined VP embedding full VCs (aud -> AMD+IBM) ===');

  const combinedPresentationPayload = {
    holder: issuerManagedDid,
    verifiableCredential: [aliceVC, bobVC, charlieVC],
    aud: audience,
  };

  const combinedVP = await infobel.agent.createVerifiablePresentation({
    presentation: combinedPresentationPayload,
    proofFormat: 'jwt',
    // proofOptions: { audience } // some veramo versions accept, but aud inside payload suffices
  });

  // Write combined VP to public folder so it can be fetched
  const combinedVpPath = path.join(infobel.publicDir, 'vp', 'combined-vp.json');
  saveJson(combinedVpPath, combinedVP);
  console.log('Combined VP saved (public):', combinedVpPath);
  console.log(`Infobel VP URL: http://localhost:${infobel.port}/vp/combined-vp.json`);

  // Also create an SDR presentation: for each VC, create a filtered credential showing only name + skills
  console.log('\n=== Infobel creates SDR VP (selective disclosure: reveal name + skills, hide homeAddress) ===');

  // Allowed fields for SDR
  const sdrFields = ['name', 'skills'];

  // Redact/copy each VC into a disclosed credential that only contains allowed fields
  const sdrCreds = [aliceVC, bobVC, charlieVC].map((vc) => redactCredentialForSdr(vc, sdrFields));

  // Create SDR presentation (signed by Infobel) with aud targeted to AMD+IBM
  const sdrPresentationPayload = {
    holder: issuerManagedDid,
    verifiableCredential: sdrCreds,
    aud: audience,
    // include a claim that this is an SDR type (optional metadata)
  };

  const sdrVP = await infobel.agent.createVerifiablePresentation({
    presentation: sdrPresentationPayload,
    proofFormat: 'jwt',
  });

  // Save SDR VP publicly (Infobel may publish it where verifiers can fetch or send directly)
  const sdrVpPath = path.join(infobel.publicDir, 'vp', 'sdr-vp.json');
  saveJson(sdrVpPath, sdrVP);
  console.log('SDR VP saved (public):', sdrVpPath);
  console.log(`Infobel SDR VP URL: http://localhost:${infobel.port}/vp/sdr-vp.json`);

  // Optionally copy the public VPs into recipients' vp folders (simulate send)
  saveJson(path.join(infos['amd'].publicDir, 'vp', 'infobel-combined-vp.json'), combinedVP);
  saveJson(path.join(infos['ibm'].publicDir, 'vp', 'infobel-combined-vp.json'), combinedVP);
  saveJson(path.join(infos['amd'].publicDir, 'vp', 'infobel-sdr-vp.json'), sdrVP);
  saveJson(path.join(infos['ibm'].publicDir, 'vp', 'infobel-sdr-vp.json'), sdrVP);

  // Now AMD & IBM verify the combined VP and the SDR VP
  console.log('\n=== AMD & IBM verification: fetch VP(s) and verify locally ===');

  async function fetchJson(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Fetch ${url} failed: ${res.status} ${res.statusText}`);
    return res.json();
  }

  function normalizeFetchedPresentation(fetched) {
    if (fetched && fetched.verifiableCredential) return fetched;
    return fetched;
  }

  async function verifyAtAgent(agentInfo, vpUrl) {
    console.log(`\n-- ${agentInfo.name.toUpperCase()} begins verification for ${vpUrl} --`);
    console.log(`${agentInfo.name} fetching VP: ${vpUrl}`);
    const fetched = await fetchJson(vpUrl);
    const presentation = normalizeFetchedPresentation(fetched);

    try {
      // Veramo's verifyPresentation will check audience; pass agentInfo.didWeb as expected audience
      const res = await agentInfo.agent.verifyPresentation({
        presentation,
        // audience should be the DID or web DID that is the verifier (agentInfo.didWeb)
        audience: agentInfo.didWeb,
      });
      console.log(`${agentInfo.name} verification result: verified=${res.verified}`);
      if (!res.verified) console.log(`${agentInfo.name} details:`, JSON.stringify(res, null, 2));
    } catch (e) {
      console.error(`${agentInfo.name} verification error:`, e);
    }
    console.log(`-- ${agentInfo.name.toUpperCase()} finished verification for ${vpUrl} --`);
  }

  // Combined VP verify
  const combinedVpUrl = `http://localhost:${infobel.port}/vp/combined-vp.json`;
  await verifyAtAgent(infos['amd'], combinedVpUrl);
  await verifyAtAgent(infos['ibm'], combinedVpUrl);

  // SDR VP verify (verifiers should accept this VP that exposes only name+skills)
  const sdrVpUrl = `http://localhost:${infobel.port}/vp/sdr-vp.json`;
  await verifyAtAgent(infos['amd'], sdrVpUrl);
  await verifyAtAgent(infos['ibm'], sdrVpUrl);

  console.log('\nDemo completed. Artifacts:');
  console.log(`  Infobel did.json: http://localhost:${infobel.port}/.well-known/did.json`);
  console.log(`  Infobel combined VP: http://localhost:${infobel.port}/vp/combined-vp.json`);
  console.log(`  Infobel SDR VP: http://localhost:${infobel.port}/vp/sdr-vp.json`);
  console.log(`  Private VCs (not exposed): ${privateVcDir}`);
  console.log('\nPress Ctrl+C to stop servers.');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
