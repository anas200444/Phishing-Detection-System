import { initializeApp } from "https://www.gstatic.com/firebasejs/12.13.0/firebase-app.js";
import { getAuth, GoogleAuthProvider } from "https://www.gstatic.com/firebasejs/12.13.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/12.13.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyCNVE28ZKDaHF3AvRrLscoy0yqrjC2z0TE",
  authDomain: "phishing-detection-syste-dc8cc.firebaseapp.com",
  projectId: "phishing-detection-syste-dc8cc",
  storageBucket: "phishing-detection-syste-dc8cc.firebasestorage.app",
  messagingSenderId: "169716347694",
  appId: "1:169716347694:web:cedf2547100d110f2300bf",
  measurementId: "G-90SXX70QMY"
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();