import { initializeApp } from "firebase/app";

const firebaseConfig = {
~>  apiKey: "@@sample:AIza[0-9A-Za-z_-]{35}@@",
  authDomain: "acme-prod.firebaseapp.com",
};

export default initializeApp(firebaseConfig);
