/**
 * vendedorGuard.js — Proteção de acesso para vendedores
 * Distribuidora Patoense 2026
 *
 * Responsabilidades:
 *  - Verificar se o usuário é um vendedor autenticado
 *  - Impedir que um vendedor acesse dados de outros vendedores
 *  - Bloquear acesso a funções exclusivas de admin
 */

import { db, doc, getDoc } from './firebase.js';
import { getFirebaseUser, getCurrentUser } from './auth.js';
import { safeError, devLog } from './security.js';

// ══════════════════════════════════════════════════════════════════
//  VERIFICAÇÃO DE VENDEDOR
// ══════════════════════════════════════════════════════════════════

/**
 * Verifica se o usuário atual é vendedor via Firestore.
 * @returns {Promise<boolean>}
 */
export async function isVendedor() {
  const fbUser = getFirebaseUser();
  if (!fbUser) return false;
  try {
    const snap = await getDoc(doc(db, 'usuarios', fbUser.uid));
    return snap.exists() && snap.data().role === 'vendedor';
  } catch (e) {
    safeError('vendedorGuard/verify', e);
    return false;
  }
}

/**
 * Retorna o perfil do vendedor atual do Firestore.
 * @returns {Promise<object|null>}
 */
export async function getVendedorProfile() {
  const fbUser = getFirebaseUser();
  if (!fbUser) return null;
  try {
    const snap = await getDoc(doc(db, 'vendedores', fbUser.uid));
    if (snap.exists()) return { uid: fbUser.uid, ...snap.data() };
    return null;
  } catch (e) {
    safeError('vendedorGuard/profile', e);
    return null;
  }
}

// ══════════════════════════════════════════════════════════════════
//  PROTEÇÃO DE FUNÇÃO — vendedores
// ══════════════════════════════════════════════════════════════════

/**
 * Executa função somente se for vendedor autenticado.
 * @param {Function} fn
 * @param {string} context
 */
export async function vendedorOnly(fn, context = '') {
  const ok = await isVendedor();
  if (!ok) {
    devLog('vendedorGuard: acesso negado', context);
    showUnauthorized();
    return;
  }
  devLog('vendedorGuard: acesso autorizado', context);
  return fn();
}

/**
 * Verifica se um pedido ou dado pertence ao vendedor logado.
 * Impede vendedor de acessar dados de outros vendedores.
 * @param {string} vendedorIdDoDado  — uid do vendedor nos dados
 * @returns {boolean}
 */
export function pertenceAoVendedor(vendedorIdDoDado) {
  const fbUser = getFirebaseUser();
  if (!fbUser) return false;
  return fbUser.uid === vendedorIdDoDado;
}

// ══════════════════════════════════════════════════════════════════
//  FILTRAGEM SEGURA — vendedor só vê seus próprios dados
// ══════════════════════════════════════════════════════════════════

/**
 * Filtra array de pedidos para mostrar somente os do vendedor atual.
 * @param {Array} pedidos
 * @returns {Array}
 */
export function filtrarPedidosDoVendedor(pedidos) {
  const fbUser = getFirebaseUser();
  if (!fbUser) return [];
  return (pedidos || []).filter(p => p.vendedorId === fbUser.uid);
}

/**
 * Filtra array de comissões para mostrar somente as do vendedor atual.
 * @param {Array} comissoes
 * @returns {Array}
 */
export function filtrarComissoesDoVendedor(comissoes) {
  const fbUser = getFirebaseUser();
  if (!fbUser) return [];
  return (comissoes || []).filter(c => c.vendedorId === fbUser.uid);
}

// ──────────────────────────────────────────────────────────────────
function showUnauthorized() {
  const msg = document.createElement('div');
  msg.style.cssText = `
    position:fixed;bottom:24px;left:50%;transform:translateX(-50%);
    background:#EF4444;color:#fff;padding:12px 24px;border-radius:10px;
    font-size:14px;font-weight:700;z-index:9999;
    box-shadow:0 4px 20px rgba(0,0,0,.3);
  `;
  msg.textContent = '⛔ Acesso restrito a vendedores autorizados';
  document.body.appendChild(msg);
  setTimeout(() => msg.remove(), 3000);
}
