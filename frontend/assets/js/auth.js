/**
 * auth.js — EVIDETH JWT Authentication Module
 *
 * Gestión centralizada del ciclo de vida del JWT en el cliente.
 * Importar en cada página antes de Alpine.js.
 *
 * Uso:
 *   Auth.requireAuth()          ← en páginas protegidas (redirige al login si no hay token)
 *   Auth.authHeader()           ← cabecera Authorization lista para fetch()
 *   Auth.logout()               ← limpia tokens y redirige al login
 *   Auth.logout({ message: 'Session expired.' })
 *   Auth.setTokens(responseData)← tras login exitoso
 */

(function (global) {
    'use strict';

    // ── localStorage keys ─────────────────────────────────────
    const K_ACCESS  = 'evideth_token';
    const K_REFRESH = 'evideth_refresh_token';
    const K_TYPE    = 'evideth_token_type';
    const K_USER    = 'evideth_user';
    const K_MSG     = 'evideth_auth_msg';   // sessionStorage, no localStorage

    const Auth = {

        // ── Almacenamiento de tokens ─────────────────────────────

        /**
         * Guarda los tokens devueltos por POST /api/v1/auth/login
         * @param {{ access_token, refresh_token, token_type, user? }} payload
         */
        setTokens(payload) {
            if (!payload || !payload.access_token) {
                throw new Error('[Auth] Missing access_token in payload');
            }
            localStorage.setItem(K_ACCESS,  payload.access_token);
            localStorage.setItem(K_TYPE,    payload.token_type || 'bearer');
            if (payload.refresh_token) {
                localStorage.setItem(K_REFRESH, payload.refresh_token);
            }
            if (payload.user) {
                localStorage.setItem(K_USER, JSON.stringify(payload.user));
            }
        },

        /** Elimina todos los datos de sesión del almacenamiento local */
        clearTokens() {
            localStorage.removeItem(K_ACCESS);
            localStorage.removeItem(K_REFRESH);
            localStorage.removeItem(K_TYPE);
            localStorage.removeItem(K_USER);
        },

        // ── Lectura de tokens ──────────────────────────────────

        getAccessToken()  { return localStorage.getItem(K_ACCESS);  },
        getRefreshToken() { return localStorage.getItem(K_REFRESH); },
        isLoggedIn()      { return !!localStorage.getItem(K_ACCESS); },

        /** Devuelve el usuario guardado o null */
        getUser() {
            try   { return JSON.parse(localStorage.getItem(K_USER)); }
            catch { return null; }
        },

        // ── Cabecera para fetch() ──────────────────────────────

        /**
         * Devuelve { Authorization: "bearer <token>" } listo para spread en fetch().
         * Si no hay token devuelve {}.
         *
         * Ejemplo:
         *   const res = await fetch('/api/v1/stats/summary', {
         *       headers: { 'Content-Type': 'application/json', ...Auth.authHeader() }
         *   });
         *   if (res.status === 401) Auth.logout({ message: 'Session expired. Please log in again.' });
         */
        authHeader() {
            const token = this.getAccessToken();
            const type  = localStorage.getItem(K_TYPE) || 'bearer';
            return token ? { 'Authorization': `${type} ${token}` } : {};
        },

        // ── Mensajes de sesión expirada ──────────────────────────

        /**
         * Guarda un mensaje en sessionStorage para mostrarlo en el login.
         * Se consume una sola vez con consumeAuthMessage().
         */
        setAuthMessage(msg) {
            sessionStorage.setItem(K_MSG, msg);
        },

        /**
         * Lee y elimina el mensaje de sesión.
         * Llamar en init() del loginApp.
         * @returns {string|null}
         */
        consumeAuthMessage() {
            const msg = sessionStorage.getItem(K_MSG);
            if (msg) sessionStorage.removeItem(K_MSG);
            return msg;
        },

        // ── Navegación y guards ───────────────────────────────

        /** URL del login, con ?return= opcional */
        loginUrl(returnUrl) {
            const base = '/frontend/pages/login/login.html';
            return returnUrl
                ? `${base}?return=${encodeURIComponent(returnUrl)}`
                : base;
        },

        /**
         * Guard de autenticación. Llamar al inicio de páginas protegidas.
         * Si no hay token redirige al login con ?return= a la URL actual.
         */
        requireAuth() {
            if (this.isLoggedIn()) return;
            window.location.href = this.loginUrl(window.location.href);
        },

        /**
         * Cierra sesión: limpia tokens y redirige al login.
         * @param {{ message?: string }} opts  Mensaje opcional para mostrar en login
         */
        logout(opts = {}) {
            if (opts.message) this.setAuthMessage(opts.message);
            this.clearTokens();
            window.location.href = this.loginUrl();
        },
    };

    // Exponer globalmente
    global.Auth = Auth;

})(window);
