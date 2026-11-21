import PocketBase from "pocketbase";

export const pb = new PocketBase("http://127.0.0.1:8090");

export const myNotes = () => pb.collection("notes").getFullList();
export const feed = () => pb.collection("messages").getList(1, 20);
