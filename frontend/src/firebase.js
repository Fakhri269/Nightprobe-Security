// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyAhs9MoNR0w7bsZSo2qDXUVxC7HDxJqpSs",
  authDomain: "nightprobe-v1.firebaseapp.com",
  projectId: "nightprobe-v1",
  storageBucket: "nightprobe-v1.firebasestorage.app",
  messagingSenderId: "242824794591",
  appId: "1:242824794591:web:d0c93892bf905c054c746a",
  measurementId: "G-NRCQ7PLLNT"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const analytics = getAnalytics(app);
