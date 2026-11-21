/// <reference path="../pb_data/types.d.ts" />
// users get a role (which they can change themselves: broken) and a plan (which they cannot).
migrate((app) => {
  const collection = app.findCollectionByNameOrId("_pb_users_auth_");
  collection.fields.add(new SelectField({ name: "role", values: ["user", "admin"], maxSelect: 1 }));
  collection.fields.add(new TextField({ name: "plan" }));
  collection.updateRule = "id = @request.auth.id && @request.body.plan:isset = false";
  return app.save(collection);
}, (app) => {
  const collection = app.findCollectionByNameOrId("_pb_users_auth_");
  collection.fields.removeByName("role");
  collection.fields.removeByName("plan");
  collection.updateRule = "id = @request.auth.id";
  return app.save(collection);
});
