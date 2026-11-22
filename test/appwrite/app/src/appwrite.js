import { Client, Databases, Storage, ID } from 'appwrite';

export const client = new Client().setEndpoint('http://localhost/v1').setProject('accessprobe-test');
export const databases = new Databases(client);
export const storage = new Storage(client);

export const addNote = (text) => databases.createDocument('main', 'notes', ID.unique(), { text, done: false });
export const myTasks = () => databases.listDocuments('main', 'tasks');
export const upload = (file) => storage.createFile('avatars', ID.unique(), file);
