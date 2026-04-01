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
import { verifyJWT } from 'did-jwt';

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

  const aliceVC = await issueVC(infobel.agent, issuerManagedDid, infos['alice'].identifier.did, 'Alice', devData.alice.skills, devData.alice.homeAddress);
  const bobVC = await issueVC(infobel.agent, issuerManagedDid, infos['bob'].identifier.did, 'Bob', devData.bob.skills, devData.bob.homeAddress);
  const charlieVC = await issueVC(infobel.agent, issuerManagedDid, infos['charlie'].identifier.did, 'Charlie', devData.charlie.skills, devData.charlie.homeAddress);

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
  // NEW HYBRID LAYER: Generating SD-JWT + Key Binding (KB) bundle objects
  console.log('\n=== NEW HYBRID LAYER: Generating SD-JWT + Key Binding (KB) ===');


  const sdjwtBundle = [];
  const sdrVcJwtList = [];

for (const name of ['alice', 'bob', 'charlie']) {

  const disclosures = [];
  const hashes = [];

  const fields = {
    name: name.charAt(0).toUpperCase() + name.slice(1),
    skills: devData[name].skills,
    // homeAddress: devData[name].homeAddress
  };

  const homefiled ={
      homeAddress : devData[name].homeAddress
  }

  for (const key of Object.keys(fields)) {
    const salt = randomHex32();

    const disclosureArr = [salt, key, fields[key]];
    const disclosureStr = JSON.stringify(disclosureArr);

    const disclosureB64 = Buffer.from(disclosureStr)
      .toString('base64url')
      .replace(/=/g, '');

    const hash = crypto
      .createHash('sha256')
      .update(disclosureStr)
      .digest('base64url')
      .replace(/=/g, '');

    disclosures.push(disclosureB64);
    hashes.push(hash);
  }

  // SD-JWT credential
  const sdCredObj = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'DeveloperCredential'],
    issuer: { id: issuerManagedDid },
    issuanceDate: new Date().toISOString(),
    credentialSubject: {
      id: infos[name].identifier.did,
      _sd: hashes
    },
    aud: audience,
  };

  const sdJwtVc = await infobel.agent.createVerifiableCredential({
    credential: sdCredObj,
    proofFormat: 'jwt'
  });

  // collect the issuer-signed SD-JWT (string) for inclusion in the SDR presentation
  if (sdJwtVc && sdJwtVc.proof && sdJwtVc.proof.jwt) {
    sdrVcJwtList.push(sdJwtVc.proof.jwt);
  }

  // Key Binding
  const kbVp = await infos[name].agent.createVerifiablePresentation({
    presentation: {
      holder: infos[name].identifier.did,
      aud: audience,
      nonce: randomHex32()
    },
    proofFormat: 'jwt'
  });

  sdjwtBundle.push({
    holder: infos[name].identifier.did,
    sd_jwt: sdJwtVc.proof.jwt,
    disclosures,
    kb_jwt: kbVp.proof.jwt
  });
}
  
// Build redacted credentials for SDR (only allowed fields)
const sdrCreds = [aliceVC, bobVC, charlieVC].map((vc) => {
  const subj = (vc.credential && vc.credential.credentialSubject) || vc.credentialSubject || {};
  const filtered = { id: subj.id };
  for (const k of sdrFields) {
    if (subj[k] !== undefined) filtered[k] = subj[k];
  }
  const issuanceDate = vc.issuanceDate || (vc.credential && vc.credential.issuanceDate) || new Date().toISOString();
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: (vc.type || (vc.credential && vc.credential.type) || ['VerifiableCredential', 'DeveloperCredential']),
    issuer: (vc.issuer || (vc.credential && vc.credential.issuer) || { id: issuerManagedDid }),
    issuanceDate,
    credentialSubject: filtered,
  };
});

  // Create SDR presentation (signed by Infobel) with aud targeted to AMD+IBM
  const sdrPresentationPayload = {
    holder: issuerManagedDid,
    // use issuer-signed SD-JWTs as verifiableCredential entries so Veramo can sign the outer presentation
    verifiableCredential: sdrVcJwtList,
    sdjwt_bundle: sdjwtBundle, // Using user's requested syntax
    aud: audience,
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

      // NEW HYBRID LAYER: Verify SD-JWT+KB if present
      const bundleList = fetched.sdjwt_bundle || (presentation && presentation.sdjwt_bundle);
      if (bundleList && bundleList.length > 0) {
         console.log(`\n${agentInfo.name} found hybrid SD-JWT+KB arrays. Verifying supplementary layer...`);
         const resolvers = {
           ...getDidKeyResolver(),
           ...getWebDidResolver(),
         };
         const resolver = new Resolver(resolvers);

         for (let i = 0; i < bundleList.length; i++) {
            const bundle = bundleList[i];
            const issuerJwt = bundle.sd_jwt;
            const disclosures = bundle.disclosures;
            const kbJwt = bundle.kb_jwt;

            console.log(`\n  --- SD-JWT+KB Document [${i}] for ${bundle.holder} ---`);
            console.log(`  -> Verifying Issuer SD-JWT Signature...`);
            const vcRes = await verifyJWT(issuerJwt, { resolver, audience: agentInfo.didWeb });
            console.log(`     ✓ SD-JWT Issuer Validated: ${vcRes.signer.id}`);
            
            console.log(`  -> Verifying Internal Disclosures...`);
            const vcPayload = vcRes.payload.vc || vcRes.payload;
            const sdHashes = vcRes.payload.vc.credentialSubject?._sd || [];
            if (!disclosures || disclosures.length === 0) console.log('     No disclosures provided.');
            for (const d of disclosures) {
               const decoded = Buffer.from(d, 'base64url').toString('utf8');
               const hash = crypto.createHash('sha256').update(decoded).digest('base64url').replace(/=/g,'');
               if (sdHashes.includes(hash)) {
                  console.log(`     ✓ Valid Disclosure Authenticated: ${decoded}`);
               } else {
                  console.log(`     ✗ INVALID DISCLOSURE: hash mismatch!`);
               }
            }

            console.log(`  -> Verifying Key Binding (KB) Signature...`);
            const kbRes = await verifyJWT(kbJwt, { resolver, audience: agentInfo.didWeb });

            // Log verification-method id returned by verifyJWT
            const vmId = kbRes.signer && kbRes.signer.id;
            console.log(`     KB signer verificationMethod: ${vmId}`);

            // Resolve the verification method DID and extract the public key material
            let resolvedVmKey = null;
            try {
              const vmDid = vmId.split('#')[0];
              const vmResolve = await resolver.resolve(vmDid);
              const vmDoc = vmResolve.didDocument || vmResolve;
              const vm = (vmDoc.verificationMethod || []).find((v) => v.id === vmId) || (vmDoc.verificationMethod && vmDoc.verificationMethod[0]);
              if (vm) {
                resolvedVmKey = vm.publicKeyJwk ? JSON.stringify(vm.publicKeyJwk) : (vm.publicKeyMultibase || vm.publicKeyHex || vm.publicKeyBase58 || vm.publicKeyBase64 || null);
                console.log(`     Resolved KB verificationMethod key: ${resolvedVmKey}`);
              } else {
                console.log('     KB verificationMethod not found in resolved DID document');
              }
            } catch (e) {
              console.log('     Error resolving KB signer DID:', e?.message || e);
            }

            // Also fetch the holder's published DID document and extract a representative key
            let holderPublishedKey = null;
            try {
              const holderResolve = await resolver.resolve(bundle.holder);
              const holderDoc = holderResolve.didDocument || holderResolve;
              const holderVm = (holderDoc.verificationMethod || []).find((v) => v.id === vmId) || (holderDoc.verificationMethod && holderDoc.verificationMethod[0]);
              if (holderVm) {
                holderPublishedKey = holderVm.publicKeyJwk ? JSON.stringify(holderVm.publicKeyJwk) : (holderVm.publicKeyMultibase || holderVm.publicKeyHex || holderVm.publicKeyBase58 || holderVm.publicKeyBase64 || null);
                console.log(`     Holder published key (from DID doc): ${holderPublishedKey}`);
              } else {
                console.log('     No verificationMethod found for holder in their DID document');
              }
            } catch (e) {
              console.log('     Error resolving holder DID:', e?.message || e);
            }

            // Compare resolved verification-method key with holder's published key (if available)
            if (resolvedVmKey && holderPublishedKey) {
              if (resolvedVmKey === holderPublishedKey) {
                console.log('     ✓ Resolved KB key and holder published key MATCH');
              } else {
                console.log('     ✗ Resolved KB key and holder published key DO NOT match');
              }
            } else {
              console.log('     (Info) Could not compare keys: one or both keys missing');
            }

            // The KB signer should match the holder ID. Some verifiers return the verification
            // method id (did#key). Normalize by stripping any fragment when comparing.
            const kbSignerDid = (kbRes.signer && kbRes.signer.id) ? kbRes.signer.id.split('#')[0] : kbRes.signer.id;
            if (kbSignerDid === bundle.holder) {
               console.log(`     ✓ Valid Key Binding by Holder: ${kbRes.signer.id}`);
            } else {
               console.log(`     ✗ INVALID KEY BINDING: signer mismatch! Expected: ${bundle.holder}, KB signer is: ${kbRes.signer.id}`);
            }
            if (vcRes.payload.sub != bundle.holder){
              console.log("X Holder mismatch between SD-JWT and KB");
            }
         }
      }

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
