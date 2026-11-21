import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rtdbPathsFromCode, ownerVarOf } from '../src/providers/firebase/rtdb-code.js';
import { shapeFromValidate, mergeTargets, rtdbTargets } from '../src/providers/firebase/rtdb-storage.js';

test('a record shape is built from .validate (hasChildren + isNumber)', () => {
  const s = shapeFromValidate(
    "newData.hasChildren(['score', 'level', 'nickname']) && newData.child('score').isNumber() && newData.child('level').isNumber()",
    'M',
  );
  assert.deepEqual(s.value, { score: 1, level: 1, nickname: 'M' });
  assert.deepEqual(s.tampered, { score: 1, level: 1, nickname: 'M-x' });
  assert.equal(shapeFromValidate(null, 'M'), null);
  assert.equal(shapeFromValidate('newData.isString()', 'M'), null);
});

test('code paths add the key level that rules leave out', () => {
  const rules = rtdbTargets(
    JSON.stringify({
      rules: {
        duel_invites: { '.read': 'auth != null', '.write': 'auth != null' },
        leaderboard: { '.read': 'auth != null', $uid: { '.write': 'auth.uid == $uid', '.validate': "newData.hasChildren(['score'])" } },
      },
    }),
  );
  const t = mergeTargets(rules, ['duel_invites/$targetUserId', 'leaderboard/$userId']);
  const by = Object.fromEntries(t.map((x) => [x.path, x]));
  assert.ok(by['duel_invites/$targetUserId']?.fromCode);
  assert.equal(by['duel_invites/$targetUserId'].ownerVar, '$targetUserId');
  assert.ok(!by['leaderboard/$userId'], 'same node as the rules entry → the rules entry (with .validate) wins');
  assert.equal(by['leaderboard/$uid'].validate, "newData.hasChildren(['score'])");
});

test('Realtime Database paths are recovered from Java/Kotlin/JS reference chains', () => {
  const java = `
    private static final String BACKUP_NODE = "backups";
    private static final String DUEL_INVITES_REF = "duel_invites";
    database = FirebaseDatabase.getInstance().getReference();
    invitesRootRef = FirebaseDatabase.getInstance().getReference(DUEL_INVITES_REF);
    DatabaseReference codeRef = database.child(BACKUP_NODE).child(code);
    DatabaseReference again = database.child(BACKUP_NODE).child(upperCode);
    invitesRootRef.child(targetUserId).child(inviteId).child("status").setValue(s);
    incomingUserRef = invitesRootRef.child(userId);
    DatabaseReference roomRef = database.child("rooms").child(roomCode);
    String n = snapshot.child("nickname").getValue(String.class);
    FirebaseDatabase.getInstance().getReference(".info/connected");`;
  const kotlin = `
    const val LEADERBOARD = "leaderboard_career"
    val ref: DatabaseReference = Firebase.database.getReference(LEADERBOARD)
    ref.child(user.getUid()).setValue(score)`;
  const paths = rtdbPathsFromCode([java, kotlin]);
  assert.deepEqual([...paths], ['backups/$code', 'duel_invites/$targetUserId', 'leaderboard_career/$uid', 'rooms/$roomCode']);
  assert.equal(ownerVarOf('duel_invites/$targetUserId'), '$targetUserId');
  assert.equal(ownerVarOf('rooms/$roomCode'), null);
  assert.ok(!paths.some((p) => p.startsWith('nickname') || p.startsWith('.info')), 'snapshots and .info are ignored');
  assert.deepEqual(paths.inboxes, ['duel_invites/$targetUserId'], 'written through a recipient id → inbox');
});

test('a recipient id that is only READ does not turn a node into an inbox', () => {
  const java = `
    presenceRootRef = FirebaseDatabase.getInstance().getReference("duel_presence");
    presenceRootRef.child(userId).child("status").setValue("online");
    presenceRootRef.child(targetUserId).child("status").get().addOnCompleteListener(x -> {});`;
  const paths = rtdbPathsFromCode([java]);
  assert.deepEqual([...paths], ['duel_presence/$userId']);
  assert.deepEqual(paths.inboxes, []);
});
