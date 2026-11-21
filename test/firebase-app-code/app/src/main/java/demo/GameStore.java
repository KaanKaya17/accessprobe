package demo;

// A tiny Android-style app WITHOUT database.rules.json: rlsprobe must find the
// Realtime Database paths from these calls and test them against the live rules.
public class GameStore {
    private static final String BACKUP_NODE = "backups";
    private static final String USERS_REF = "users";
    private final DatabaseReference database = FirebaseDatabase.getInstance().getReference();
    private final DatabaseReference usersRef = FirebaseDatabase.getInstance().getReference(USERS_REF);

    void saveProfile(String uid, Profile p) {
        usersRef.child(uid).child("profile").setValue(p);
    }

    void backup(String code, Object data) {
        database.child(BACKUP_NODE).child(code).setValue(data);
    }

    void invite(String targetUserId, Invite inv) {
        database.child("invites").child(targetUserId).push().setValue(inv);
    }

    void read(DataSnapshot snapshot) {
        snapshot.child("ignored").getValue(String.class); // DataSnapshot, not a path
    }

    void connected() {
        FirebaseDatabase.getInstance().getReference(".info/connected");
    }
}
