/**
 * firebase.js — Inicialização segura do Firebase
 * Distribuidora Patoense 2026
 *
 * ⚠️  A apiKey do Firebase para apps web NÃO é um segredo —
 *     ela só identifica o projeto. A segurança real está nas
 *     Firestore Rules e no Firebase Authentication.
 *     Ref: https://firebase.google.com/docs/projects/api-keys
 *
 * O que protege seus dados:
 *  1. Firestore Rules (firestore.rules) — define quem lê/escreve o quê
 *  2. Firebase Auth — garante que o usuário é quem diz ser
 *  3. Headers HTTP (_headers) — proteção de transporte e XSS
 */

import { initializeApp }             from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getFirestore, doc, setDoc, getDoc, addDoc, collection,
         onSnapshot, updateDoc, deleteDoc, serverTimestamp, getDocs }
  from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import { getAuth, signInWithEmailAndPassword, signOut,
         onAuthStateChanged, sendPasswordResetEmail }
  from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

// ── Configuração do projeto (não é segredo — ver nota acima) ────
const firebaseConfig = {
  apiKey:            "AIzaSyAT_QlSjBNcKjaxUB6T7zpslCo-WCJlUJ4",
  authDomain:        "catalogo-patoense2-2600c.firebaseapp.com",
  projectId:         "catalogo-patoense2-2600c",
  storageBucket:     "catalogo-patoense2-2600c.firebasestorage.app",
  messagingSenderId: "260989078744",
  appId:             "1:260989078744:web:658a3cb0aac3cc4abf5bad"
};

// ── Inicialização ────────────────────────────────────────────────
const app  = initializeApp(firebaseConfig);
const db   = getFirestore(app);
const auth = getAuth(app);

// ── Exporta para uso nos outros módulos ─────────────────────────
// NÃO expõe no window — acesso apenas via import
export {
  db, auth,
  doc, setDoc, getDoc, addDoc, collection,
  onSnapshot, updateDoc, deleteDoc, serverTimestamp, getDocs,
  signInWithEmailAndPassword, signOut,
  onAuthStateChanged, sendPasswordResetEmail
};
