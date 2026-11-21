/// <reference path="../pb_data/types.d.ts" />
// accessprobe test fixture: a mix of broken and correct API rules.
migrate((app) => {
  const owner = { name: "user", type: "relation", collectionId: "_pb_users_auth_", maxSelect: 1, required: true, cascadeDelete: false };

  // correct: owner-only everything, owner field locked on update
  app.save(new Collection({
    type: "base",
    name: "notes",
    listRule: "user = @request.auth.id",
    viewRule: "user = @request.auth.id",
    createRule: "@request.auth.id != \"\" && @request.body.user = @request.auth.id",
    updateRule: "user = @request.auth.id && (@request.body.user:isset = false || @request.body.user = @request.auth.id)",
    deleteRule: "user = @request.auth.id",
    fields: [{ name: "text", type: "text" }, owner],
  }));

  // leaky: every signed-in user may LIST everything (view is owner-only)
  app.save(new Collection({
    type: "base",
    name: "messages",
    listRule: "@request.auth.id != \"\"",
    viewRule: "user = @request.auth.id",
    createRule: "@request.auth.id != \"\" && @request.body.user = @request.auth.id",
    updateRule: "user = @request.auth.id && @request.body.user:isset = false",
    deleteRule: "user = @request.auth.id",
    fields: [{ name: "body", type: "text" }, owner],
  }));

  // forgery: create checks only that someone is signed in, not who the owner is
  app.save(new Collection({
    type: "base",
    name: "orders",
    listRule: "user = @request.auth.id",
    viewRule: "user = @request.auth.id",
    createRule: "@request.auth.id != \"\"",
    updateRule: "user = @request.auth.id && @request.body.user:isset = false",
    deleteRule: "user = @request.auth.id",
    fields: [{ name: "item", type: "text" }, owner],
  }));

  // takeover: update checks only the NEW owner value
  app.save(new Collection({
    type: "base",
    name: "claims",
    listRule: "user = @request.auth.id",
    viewRule: "user = @request.auth.id",
    createRule: "@request.auth.id != \"\" && @request.body.user = @request.auth.id",
    updateRule: "@request.body.user = @request.auth.id",
    deleteRule: "user = @request.auth.id",
    fields: [{ name: "title", type: "text" }, owner],
  }));

  // public on purpose: anyone may read, only the owner may write
  app.save(new Collection({
    type: "base",
    name: "posts",
    listRule: "",
    viewRule: "",
    createRule: "@request.auth.id != \"\" && @request.body.user = @request.auth.id",
    updateRule: "user = @request.auth.id && @request.body.user:isset = false",
    deleteRule: "user = @request.auth.id",
    fields: [{ name: "title", type: "text" }, owner],
  }));

  // read-only for users; access depends on fields of the caller's own user record
  app.save(new Collection({
    type: "base",
    name: "admin_reports",
    listRule: "@request.auth.role = \"admin\"",
    viewRule: "@request.auth.role = \"admin\"",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [{ name: "summary", type: "text" }],
  }));
  app.save(new Collection({
    type: "base",
    name: "premium_videos",
    listRule: "@request.auth.plan = \"pro\"",
    viewRule: "@request.auth.plan = \"pro\"",
    createRule: null,
    updateRule: null,
    deleteRule: null,
    fields: [{ name: "url", type: "text" }],
  }));
}, (app) => {
  for (const name of ["notes", "messages", "orders", "claims", "posts", "admin_reports", "premium_videos"]) {
    app.delete(app.findCollectionByNameOrId(name));
  }
});
