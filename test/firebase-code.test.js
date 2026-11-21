import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rtdbPathsFromCode, ownerVarOf } from '../src/providers/firebase/rtdb-code.js';

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
  assert.deepEqual(paths, ['backups/$code', 'duel_invites/$targetUserId', 'leaderboard_career/$uid', 'rooms/$roomCode']);
  assert.equal(ownerVarOf('duel_invites/$targetUserId'), '$targetUserId');
  assert.equal(ownerVarOf('rooms/$roomCode'), null);
  assert.ok(!paths.some((p) => p.startsWith('nickname') || p.startsWith('.info')), 'snapshots and .info are ignored');
});
