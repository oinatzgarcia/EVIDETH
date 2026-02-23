/**
 * profile-menu.js — EVIDETH Profile Dropdown Component
 *
 * Componente Alpine.js reutilizable para el menú de perfil de usuario.
 * Muestra nombre, email, rol del usuario autenticado y botón de cerrar sesión.
 *
 * Uso:
 *   <div x-data="profileMenu()" @keydown.escape.window="open = false">
 *     ...
 *   </div>
 *
 * Requiere auth.js cargado previamente (Auth.getUser()).
 */

function profileMenu() {
    // Leemos el usuario en el momento de inicialización del componente.
    // Auth.getUser() devuelve el objeto guardado por Auth.setTokens() en el login.
    const u = (typeof Auth !== 'undefined') ? Auth.getUser() : null;

    return {
        open:    false,
        _user:   u,
        isAdmin: !!(u && u.role === 'admin'),

        /** Nombre completo del usuario */
        fullName() {
            return this._user?.full_name || 'Usuario';
        },

        /** Email del usuario */
        email() {
            return this._user?.email || '';
        },

        /** Rol del usuario (admin | analyst | viewer) */
        role() {
            return this._user?.role || 'viewer';
        },

        /**
         * Iniciales para el avatar circular.
         * "María García" → "MG"  |  "admin" → "AD"
         */
        initials() {
            const name = this._user?.full_name || 'U';
            return name
                .trim()
                .split(/\s+/)
                .slice(0, 2)
                .map(w => w[0].toUpperCase())
                .join('');
        },

        /** Cierra sesión y redirige al login */
        logout() {
            if (typeof Auth !== 'undefined') {
                Auth.logout({ message: 'Sesión cerrada. Inicia sesión de nuevo.' });
            }
        },
    };
}
