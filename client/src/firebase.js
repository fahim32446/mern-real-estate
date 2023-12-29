import { initializeApp } from 'firebase/app';
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: 'AIzaSyAV7mG7CIdqFrADEg0mS25iwSteat59IC4',
  authDomain: 'oauthforrealstate.firebaseapp.com',
  projectId: 'oauthforrealstate',
  storageBucket: 'oauthforrealstate.appspot.com',
  messagingSenderId: '855625503908',
  appId: '1:855625503908:web:b1a10b8b2c22027ee78231',
};

// Initialize Firebase
export const app = initializeApp(firebaseConfig);
