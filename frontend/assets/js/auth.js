/**
 * auth.js — EVIDETH JWT Authentication Module
 *
 * Gestión centralizada del ciclo de vida del JWT en el cliente.
 * Importar en cada página ANTES de Alpine.js.
 *
 * Uso básico:
 *   Auth.setTokens(data, rememberMe)  ← tras login exitoso
 *   Auth.requireAuth()                ← guard en páginas protegidas
 *   Auth.authHeader()                 ← cabecera Authorization para fetch()
 *   Auth.logout()                     ← limpia sesión y redirige
 *   Auth.logout({ message: 'txt' })   ← con mensaje de sesión expirada
 *
 * Modo "Recordar sesión":
 *   rememberMe = true  → tokens en localStorage  (persiste al cerrar el navegador)
 *   rememberMe = false → tokens en sessionStorage (se borra al cerrar la pestaña)
 */

(function (global) {
    'use strict';

    // ── Storage keys ────────────────────────────────────────
    const K_ACCESS     = 'evideth_token';
    const K_REFRESH    = 'evideth_refresh_token';
    const K_TYPE       = 'evideth_token_type';
    const K_USER       = 'evideth_user';
    const K_MSG        = 'evideth_auth_msg';    // sessionStorage — one-shot message
    const K_STORE_TYPE = 'evideth_store';       // localStorage  — 'local' | 'session'

    const Auth = {

        // ── Helper interno: devuelve el storage donde están los tokens ─────

        /**
         * Lee el flag K_STORE_TYPE y devuelve localStorage o sessionStorage.
         * Si no hay flag (primera visita) asume sessionStorage.
         */
        _store() {
            return localStorage.getItem(K_STORE_TYPE) === 'local'
                ? localStorage
                : sessionStorage;
        },

        // ── Almacenamiento de tokens ───────────────────────────────

        /**
         * Guarda los tokens devueltos por POST /api/v1/auth/login.
         * @param {{ access_token, refresh_token, token_type, user? }} payload
         * @param {boolean} rememberMe  true → localStorage | false → sessionStorage
         */
        setTokens(payload, rememberMe = false) {
            if (!payload || !payload.access_token) {
                throw new Error('[Auth] Missing access_token in payload');
            }

            // El flag SIEMPRE en localStorage para saber dónde buscar más tarde
            localStorage.setItem(K_STORE_TYPE, rememberMe ? 'local' : 'session');

            const store = rememberMe ? localStorage : sessionStorage;
            store.setItem(K_ACCESS, payload.access_token);
            store.setItem(K_TYPE,   payload.token_type || 'bearer');
            if (payload.refresh_token) store.setItem(K_REFRESH, payload.refresh_token);
            if (payload.user)          store.setItem(K_USER, JSON.stringify(payload.user));
        },

        /** Elimina tokens de AMBOS storages (seguro en cualquier modo) */
        clearTokens() {
            [localStorage, sessionStorage].forEach(s => {
                s.removeItem(K_ACCESS);
                s.removeItem(K_REFRESH);
                s.removeItem(K_TYPE);
                s.removeItem(K_USER);
            });
            localStorage.removeItem(K_STORE_TYPE);
        },

        // ── Lectura de tokens ───────────────────────────────────

        getAccessToken()  { return this._store().getItem(K_ACCESS);  },
        getRefreshToken() { return this._store().getItem(K_REFRESH); },
        isLoggedIn()      { return !!this._store().getItem(K_ACCESS); },

        /** Devuelve el objeto user guardado, o null */
        getUser() {
            try   { return JSON.parse(this._store().getItem(K_USER)); }
            catch { return null; }
        },

        /** true si el usuario marcó "recordar sesión" */
        isRemembered() {
            return localStorage.getItem(K_STORE_TYPE) === 'local';
        },

        // ── Cabecera para fetch() ────────────────────────────────

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
            const type  = this._store().getItem(K_TYPE) || 'bearer';
            return token ? { 'Authorization': `${type} ${token}` } : {};
        },

        // ── Mensajes de sesión expirada ──────────────────────────

        /** Guarda un mensaje para mostrarlo en el login (one-shot) */
        setAuthMessage(msg) {
            sessionStorage.setItem(K_MSG, msg);
        },

        /**
         * Lee y elimina el mensaje. Llamar en init() del loginApp.
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
         * Si no hay token, redirige al login con ?return= a la URL actual.
         */
        requireAuth() {
            if (this.isLoggedIn()) return;
            global.location.href = this.loginUrl(global.location.href);
        },

        /**
         * Cierra sesión: limpia tokens y redirige al login.
         * @param {{ message?: string }} opts  Mensaje opcional para el login
         */
        logout(opts = {}) {
            if (opts.message) this.setAuthMessage(opts.message);
            this.clearTokens();
            global.location.href = this.loginUrl();
        },
    };

    // Exponer globalmente
    global.Auth = Auth;

})(window);
