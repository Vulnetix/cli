import { initializeApp } from "firebase/app";
const firebaseConfig = {
  apiKey: "@@sample:AIza[0-9A-Za-z_-]{35}@@",
  authDomain: "demo-app.firebaseapp.com",
  projectId: "demo-app",
};
export const app = initializeApp(firebaseConfig);
