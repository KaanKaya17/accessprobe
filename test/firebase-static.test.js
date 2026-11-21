import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRules, allowsFor, ownerField, ownerPathVar, staticFlags, collectionOf } from '../src/providers/firebase/rules.js';
import { extract, fromGoogleServicesJson, fromPlist } from '../src/providers/firebase/discover.js';

// fake web API key, assembled at runtime so secret scanners don't flag the test file
const FAKE_WEB_KEY = ['AIza', 'SyA1234567890abcdefghijklmnopqrstuv'].join('');

const RULES = `rules_version = '2';
// comment with match /fake/{x} { allow read: if true; }
service cloud.firestore {
  match /databases/{database}/documents {
    function signedIn() { return request.auth != null; }
    function isOwner(uid) { return request.auth.uid == uid; }

    match /profiles/{uid} {
      allow read: if signedIn();
      allow write: if isOwner(uid);
    }
    match /orders/{id} {
      allow read, create: if request.auth != null;
      allow update, delete: if resource.data.userId == request.auth.uid;
    }
    match /users/{uid} {
      match /private/{doc} {
        allow read, write: if request.auth.uid == uid;
      }
    }
    match /legacy/{id} {
      allow read, write: if request.time < timestamp.date(2026, 12, 1);
    }
    match /{document=**} {
      allow read: if true;
    }
  }
}`;

test('parses nested matches, inlines functions, finds ownership', () => {
  const ms = parseRules(RULES);
  const by = Object.fromEntries(ms.map((m) => [m.path, m]));
  assert.deepEqual(Object.keys(by).sort(), ['/legacy/{id}', '/orders/{id}', '/profiles/{uid}', '/users/{uid}/private/{doc}', '/{document=**}'].sort());
  assert.ok(!('/fake/{x}' in by), 'comments are ignored');

  assert.deepEqual(allowsFor(by['/profiles/{uid}'], 'list'), ['(request.auth != null)']);
  assert.equal(ownerPathVar(by['/profiles/{uid}']), 'uid', 'found through the inlined isOwner(uid)');
  assert.equal(ownerField(by['/orders/{id}']), 'userId');
  assert.deepEqual(allowsFor(by['/orders/{id}'], 'create'), ['request.auth != null']);
  assert.equal(ownerPathVar(by['/users/{uid}/private/{doc}']), 'uid');
  assert.deepEqual(collectionOf(by['/users/{uid}/private/{doc}']), { collectionPath: 'users/{uid}/private', docVar: 'doc' });
  assert.equal(collectionOf(by['/{document=**}']), null);

  assert.equal(staticFlags(by['/legacy/{id}'])[0].kind, 'test-mode-expiry');
  assert.equal(staticFlags(by['/{document=**}'])[0].kind, 'catch-all-open');
});

test('finds firebaseConfig in a minified bundle and flags service account keys', () => {
  const js =
    'var a=initializeApp({apiKey:"' + FAKE_WEB_KEY + '",authDomain:"shop-demo.firebaseapp.com",' +
    'projectId:"shop-demo",storageBucket:"shop-demo.appspot.com",databaseURL:"https://shop-demo-default-rtdb.firebaseio.com",appId:"1:2:web:3"});' +
    'const sa={"type": "service_account","project_id":"shop-demo","private_key": "-----BEGIN PRIVATE KEY-----\\nMIIE"};';
  const r = extract([{ where: 'app.js', text: js }]);
  assert.equal(r.configs.length, 1);
  assert.deepEqual(
    { ...r.configs[0], where: undefined },
    {
      apiKey: FAKE_WEB_KEY,
      projectId: 'shop-demo',
      databaseURL: 'https://shop-demo-default-rtdb.firebaseio.com',
      storageBucket: 'shop-demo.appspot.com',
      authDomain: 'shop-demo.firebaseapp.com',
      where: undefined,
    },
  );
  assert.equal(r.findings[0].id, 'leaked-firebase-service-account');
  assert.ok(!r.findings[0].evidence.includes('MIIE'), 'evidence is redacted');
});

test('reads Android and iOS config files', () => {
  const g = fromGoogleServicesJson(
    JSON.stringify({
      project_info: { project_id: 'p1', firebase_url: 'https://p1.firebaseio.com', storage_bucket: 'p1.appspot.com' },
      client: [{ api_key: [{ current_key: 'AIzaX' }] }],
    }),
  );
  assert.equal(g.projectId, 'p1');
  assert.equal(g.apiKey, 'AIzaX');
  const p = fromPlist('<dict><key>API_KEY</key><string>AIzaY</string><key>PROJECT_ID</key><string>p2</string></dict>');
  assert.equal(p.projectId, 'p2');
  assert.equal(fromGoogleServicesJson('{bad'), null);
});

test('privilegeFields: fields read from the caller\'s own document that grant rights', async () => {
  const { privilegeFields } = await import('../src/providers/firebase/rules.js');
  const rules = `service cloud.firestore { match /databases/{database}/documents {
    function isAdmin() { return get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin'; }
    match /reports/{id} { allow read: if isAdmin(); }
    match /vip/{id} { allow read: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.isPro; }
    match /mods/{id} { allow read: if get(/databases/$(database)/documents/accounts/$(request.auth.uid)).data.tier in ["gold", "silver"]; }
    match /x/{id} { allow read: if get(/databases/$(database)/documents/users/$(request.auth.uid)).data.banned != true; }
  } }`;
  const p = privilegeFields(parseRules(rules));
  assert.deepEqual(p.get('users'), [
    { field: 'role', value: 'admin' },
    { field: 'isPro', value: true },
  ]);
  assert.deepEqual(p.get('accounts'), [{ field: 'tier', value: 'gold' }]);
});
