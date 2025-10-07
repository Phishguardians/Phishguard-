import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyAQAhTvnZC645lQO7s_FdUEXKw1dU-1e8I",
  authDomain: "phishguard7.firebaseapp.com",
  projectId: "phishguard7",
  storageBucket: "phishguard7.firebasestorage.app",
  messagingSenderId: "584877065949",
  appId: "1:584877065949:web:8bfe1ca7e7036cfc4f7d34",
  measurementId: "G-88YHYJR12P"
};


const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();
export const db = getFirestore(app);
