/**
 * authorize.js — Camada centralizada de autorização
 * Distribuidora Patoense 2026
 *
 * [AUTHZ] Substitui verificações espalhadas por uma API unificada.
 *
 * USO:
 *   import { authorize } from './authorize.js';
 *
 *   // Exemplo 1 — verificação simples:
 *   if (!await authorize('delete', produto)) return;
 *
 *   // Exemplo 2 — com opções:
 *   const result = await authorize('read', pedido, { strong: false });
 *   if (!result.ok) { showError(result.msg); return; }
 *
 *   // Exemplo 3 — ação crítica (confirma no Firestore):
 *   await authorize('approve', cliente, { strong: true, onDeny: () => redirect() });
 *
 * AÇÕES SUPORTADAS:
 *   Ação            | Quem pode
 *   ─────────────────────────────────────────────────
 *   read            | admin, vendedor (próprios dados), cliente (próprios dados)
 *   write           | admin, vendedor (próprios dados)
 *   delete          | admin (strong=true obrigatório)
 *   approve         | admin (strong=true obrigatório)
 *   list            | admin
 *   export          | admin
 *   audit           | admin
 *   vendedor:read   | vendedor autenticado (próprios dados)
 *   vendedor:write  | vendedor autenticado (próprios dados)
 *   cliente:read    | cliente logado (próprios dados)
 *   cliente:write   | cliente logado (próprios dados)
 */

import { getIsAdmin, getFirebaseUser, getCurrentUser } from './auth.js';
import { isAdminFirestore }                            from './adminGuard.js';
import { isVendedor }                                  from './vendedorGuard.js';
import { devLog, safeError }                           from './security.js';

// ══════════════════════════════════════════════════════════════════
//  MAPA DE POLÍTICAS
//  Define quais roles podem executar cada ação
//  e se exige verificação forte no Firestore
// ══════════════════════════════════════════════════════════════════

const _policies = {
  // Ações administrativas — sempre exigem admin
  'delete':   { roles: ['admin'], strong: true  },
  'approve':  { roles: ['admin'], strong: true  },
  'list':     { roles: ['admin'], strong: false },
  'export':   { roles: ['admin'], strong: true  },
  'audit':    { roles: ['admin'], strong: false },

  // Leitura genérica — admin ou dono do recurso
  'read':     { roles: ['admin', 'vendedor', 'cliente'], strong: false, ownerCheck: true },

  // Escrita genérica — admin ou vendedor (dono)
  'write':    { roles: ['admin', 'vendedor'], strong: false, ownerCheck: true },

  // Ações específicas de vendedor
  'vendedor:read':  { roles: ['vendedor'], strong: false, ownerCheck: true },
  'vendedor:write': { roles: ['vendedor'], strong: false, ownerCheck: true },

  // Ações específicas de cliente
  'cliente:read':   { roles: ['cliente'], strong: false, ownerCheck: true },
  'cliente:write':  { roles: ['cliente'], strong: false, ownerCheck: true },
};

// ══════════════════════════════════════════════════════════════════
//  AUTHORIZE — API PRINCIPAL
// ══════════════════════════════════════════════════════════════════

/**
 * Verifica se o usuário atual pode executar `action` sobre `resource`.
 *
 * @param {string}  action    — nome da ação (ver mapa de políticas)
 * @param {object}  resource  — objeto com `vendedorId` ou `clienteId`
 *                              para verificação de ownership (opcional)
 * @param {object}  opts
 * @param {boolean} opts.strong   — força verificação no Firestore
 *                                  (sobrescreve o padrão da política)
 * @param {Function} opts.onDeny  — callback chamado se negado (opcional)
 *
 * @returns {Promise<{ ok: boolean, msg?: string, role?: string }>}
 */
export async function authorize(action, resource = {}, opts = {}) {
  const policy = _policies[action];

  if (!policy) {
    safeError('authorize/unknown-action', action);
    return { ok: false, msg: 'Ação desconhecida.' };
  }

  const useStrong = opts.strong !== undefined ? opts.strong : policy.strong;
  let   role      = null;

  try {
    // ── Determina a role atual ──────────────────────────────────
    if (getIsAdmin()) {
      role = 'admin';
    } else if (getCurrentUser() && !getCurrentUser().isAdmin) {
      // Pode ser vendedor ou cliente — verificamos o contexto
      const fbUser = getFirebaseUser();
      if (fbUser) {
        // Firebase user presente → potencialmente vendedor
        const vendedor = await isVendedor();
        role = vendedor ? 'vendedor' : 'cliente';
      } else {
        role = 'cliente';
      }
    }

    // ── Checa se a role está autorizada ────────────────────────
    if (!role || !policy.roles.includes(role)) {
      return _deny(action, role, opts.onDeny, 'role não autorizada');
    }

    // ── Verificação forte no Firestore (ações críticas) ─────────
    if (useStrong && role === 'admin') {
      const confirmed = await isAdminFirestore();
      if (!confirmed) {
        return _deny(action, role, opts.onDeny, 'confirmação Firestore falhou');
      }
    }

    // ── Verificação de ownership (ownerCheck) ───────────────────
    if (policy.ownerCheck && role !== 'admin') {
      const allowed = _checkOwnership(role, resource);
      if (!allowed) {
        return _deny(action, role, opts.onDeny, 'ownership check falhou');
      }
    }

    devLog(`authorize: [${role}] PERMITIDO → ${action}`);
    return { ok: true, role };

  } catch (e) {
    safeError('authorize/error', e);
    return _deny(action, role, opts.onDeny, 'erro interno');
  }
}

// ══════════════════════════════════════════════════════════════════
//  HELPERS INTERNOS
// ══════════════════════════════════════════════════════════════════

/**
 * Verifica se o recurso pertence ao usuário atual.
 * @param {string} role
 * @param {object} resource
 * @returns {boolean}
 */
function _checkOwnership(role, resource) {
  if (!resource) return true; // sem recurso, não verifica ownership

  const fbUser     = getFirebaseUser();
  const clientUser = getCurrentUser();

  if (role === 'vendedor') {
    if (!fbUser) return false;
    // Recurso deve ter vendedorId igual ao UID do vendedor logado
    return !resource.vendedorId || resource.vendedorId === fbUser.uid;
  }

  if (role === 'cliente') {
    if (!clientUser) return false;
    const digits = (clientUser.tel || '').replace(/\D/g, '');
    // Recurso deve pertencer ao cliente logado (por tel ou clienteId)
    if (resource.clienteId) return resource.clienteId === digits;
    if (resource.tel)       return resource.tel.replace(/\D/g, '') === digits;
    return true; // recurso sem ID de cliente, permite (para próprio perfil)
  }

  return false;
}

/**
 * Cria resultado de negação e chama callback se fornecido.
 */
function _deny(action, role, onDeny, reason = '') {
  devLog(`authorize: [${role || 'anon'}] NEGADO → ${action} (${reason})`);
  if (typeof onDeny === 'function') onDeny();
  return { ok: false, msg: 'Ação não autorizada.' };
}

// ══════════════════════════════════════════════════════════════════
//  WRAPPERS DE CONVENIÊNCIA
//  Para uso nos módulos existentes (adminGuard, vendedorGuard)
// ══════════════════════════════════════════════════════════════════

/**
 * Guard para ações administrativas. Substitui adminOnly().
 * @param {Function} fn
 * @param {boolean}  strong
 * @param {string}   context
 */
export async function adminAction(fn, strong = false, context = '') {
  const result = await authorize(strong ? 'delete' : 'list', {}, { strong });
  if (!result.ok) {
    devLog('adminAction: negado', context);
    _showUnauthorized('⛔ Acesso não autorizado');
    return;
  }
  devLog('adminAction: autorizado', context);
  return fn();
}

/**
 * Guard para ações de vendedor. Substitui vendedorOnly().
 * @param {Function} fn
 * @param {object}   resource
 * @param {string}   context
 */
export async function vendedorAction(fn, resource = {}, context = '') {
  const result = await authorize('vendedor:read', resource);
  if (!result.ok) {
    devLog('vendedorAction: negado', context);
    _showUnauthorized('⛔ Acesso restrito a vendedores autorizados');
    return;
  }
  devLog('vendedorAction: autorizado', context);
  return fn();
}

function _showUnauthorized(msg) {
  const el = document.createElement('div');
  el.style.cssText = `
    position:fixed;bottom:24px;left:50%;transform:translateX(-50%);
    background:#EF4444;color:#fff;padding:12px 24px;border-radius:10px;
    font-size:14px;font-weight:700;z-index:9999;
    box-shadow:0 4px 20px rgba(0,0,0,.3);
  `;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}
