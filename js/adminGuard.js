/**
 * adminGuard.js — Proteção de rotas e funções administrativas
 * Distribuidora Patoense 2026
 *
 * Responsabilidades:
 *  - Verificar se o usuário atual é admin antes de qualquer ação admin
 *  - Bloquear acesso a funções administrativas
 *  - Validar permissão em tempo real (não confia em cache)
 *
 * Princípio: verificação dupla
 *  1. Estado local (_isAdmin) — evita chamada Firebase para cada clique
 *  2. Firestore — confirma role para ações destrutivas (apagar, aprovar)
 */

import { db, doc, getDoc } from './firebase.js';
import { getIsAdmin, getFirebaseUser } from './auth.js';
import { safeError, devLog } from './security.js';

// ══════════════════════════════════════════════════════════════════
//  GUARD PRINCIPAL — uso em todas as funções admin
// ══════════════════════════════════════════════════════════════════

/**
 * Verifica rapidamente (estado local) se o usuário é admin.
 * Use para guards de UI (mostrar/ocultar botões).
 * @returns {boolean}
 */
export function isAdminLocal() {
  return getIsAdmin() === true;
}

/**
 * Verificação forte: confirma admin no Firestore.
 * Use antes de operações destrutivas ou sensíveis.
 * @returns {Promise<boolean>}
 */
export async function isAdminFirestore() {
  const fbUser = getFirebaseUser();
  if (!fbUser) return false;
  try {
    const snap = await getDoc(doc(db, 'usuarios', fbUser.uid));
    return snap.exists() && snap.data().role === 'admin';
  } catch (e) {
    safeError('adminGuard/verify', e);
    return false;
  }
}

// ══════════════════════════════════════════════════════════════════
//  PROTEÇÃO DE FUNÇÃO — wrapper para ações admin
// ══════════════════════════════════════════════════════════════════

/**
 * Executa uma função somente se o usuário for admin.
 * Para ações normais: verifica estado local (rápido).
 * Para ações críticas (strong=true): verifica no Firestore.
 *
 * @param {Function} fn       — função a executar
 * @param {boolean}  strong   — true = verificação Firestore
 * @param {string}   context  — nome para log de auditoria
 * @returns {Promise<any>}
 */
export async function adminOnly(fn, strong = false, context = '') {
  // Verificação local rápida
  if (!isAdminLocal()) {
    devLog('adminGuard: acesso negado (local)', context);
    showUnauthorized();
    return;
  }

  // Verificação forte no Firestore (para ações críticas)
  if (strong) {
    const confirmed = await isAdminFirestore();
    if (!confirmed) {
      devLog('adminGuard: acesso negado (Firestore)', context);
      showUnauthorized();
      return;
    }
  }

  devLog('adminGuard: acesso autorizado', context);
  return fn();
}

// ══════════════════════════════════════════════════════════════════
//  PROTEÇÃO DO PAINEL ADMIN — esconde e bloqueia DOM
// ══════════════════════════════════════════════════════════════════

/**
 * Aplica proteção ao painel admin no DOM.
 * Chamado ao carregar a página e ao mudar estado de auth.
 * @param {boolean} isAdmin
 */
export function applyAdminGuardDOM(isAdmin) {
  const adminPanel   = document.getElementById('adminPanel');
  const admHeaderBtn = document.getElementById('admHeaderBtn');
  const admLoginBtn  = document.getElementById('admLoginBtn');

  if (!isAdmin) {
    // Oculta e desabilita o painel
    if (adminPanel) {
      adminPanel.style.display = 'none';
      // Remove listener de teclado secreto se existir
    }
    if (admHeaderBtn) admHeaderBtn.style.display = 'none';
  } else {
    if (admHeaderBtn) admHeaderBtn.style.display = 'flex';
  }
}

/**
 * Verifica se o painel admin está sendo acessado por não-admin
 * e fecha/bloqueia se necessário. Chamado periodicamente.
 */
export function enforceAdminPanelAccess() {
  const adminPanel = document.getElementById('adminPanel');
  if (!adminPanel) return;

  const isVisible = adminPanel.style.display !== 'none' &&
                    adminPanel.style.visibility !== 'hidden';

  if (isVisible && !isAdminLocal()) {
    devLog('adminGuard: fechando painel aberto indevidamente');
    adminPanel.style.display = 'none';
  }
}

// ══════════════════════════════════════════════════════════════════
//  UI DE ACESSO NEGADO
// ══════════════════════════════════════════════════════════════════

function showUnauthorized() {
  // Toast discreto — não expõe detalhes de segurança
  const msg = document.createElement('div');
  msg.style.cssText = `
    position:fixed;bottom:24px;left:50%;transform:translateX(-50%);
    background:#EF4444;color:#fff;padding:12px 24px;border-radius:10px;
    font-size:14px;font-weight:700;z-index:9999;
    box-shadow:0 4px 20px rgba(0,0,0,.3);
  `;
  msg.textContent = '⛔ Acesso não autorizado';
  document.body.appendChild(msg);
  setTimeout(() => msg.remove(), 3000);
}

// ══════════════════════════════════════════════════════════════════
//  AUDITORIA — lista de ações admin críticas
// ══════════════════════════════════════════════════════════════════

/**
 * Registra ação administrativa para auditoria.
 * Salva no Firestore apenas se admin confirmado.
 * @param {string} acao   — ex: 'aprovar_cliente', 'deletar_produto'
 * @param {object} dados  — dados relevantes (sem senhas)
 */
export async function auditarAcao(acao, dados = {}) {
  const fbUser = getFirebaseUser();
  if (!fbUser) return;

  try {
    const { addDoc, collection, serverTimestamp } = await import('./firebase.js');
    await addDoc(collection(db, 'auditoria'), {
      acao,
      dados:     sanitizarDados(dados),
      adminUid:  fbUser.uid,
      adminEmail: fbUser.email,
      criadoEm:  serverTimestamp(),
      ip:        null // não é possível pegar IP real no frontend
    });
  } catch (e) {
    // Auditoria não deve quebrar o fluxo principal
    safeError('adminGuard/audit', e);
  }
}

function sanitizarDados(dados) {
  // Remove campos sensíveis antes de salvar na auditoria
  const proibidos = ['senha', 'senhaHash', 'password', 'token', 'secret'];
  const limpo = { ...dados };
  proibidos.forEach(k => delete limpo[k]);
  return limpo;
}
