import { initializeApp } from "firebase/app";
const firebaseConfig = {
~>  apiKey: "@@sample:AIza[A-Za-z0-9_-]{35}@@",
  authDomain: "shop-prod.firebaseapp.com",
  projectId: "shop-prod",
};
export const app = initializeApp(firebaseConfig);
