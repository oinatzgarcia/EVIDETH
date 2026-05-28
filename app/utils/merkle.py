"""
Merkle Tree para verificación EVIDETH a nivel de segundo.

Basado en el árbol Merkle binario de Bitcoin:
- Hojas    = SHA-256 de chunks de 1 segundo del segmento
- Padre    = SHA-256(hijo_izq ‖ hijo_der)
- Impar    = se duplica el último nodo (convención Bitcoin)

El Merkle Root identifica unívocamente el contenido de un segmento de 30 s.
Si la raíz no coincide con la almacenada → se pueden localizar exactamente
los segundos manipulados sin necesidad de retransmitir el segmento completo.

Referencias:
  - NIST FIPS 180-4  (SHA-256)
  - Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash System, §7
"""

import hashlib
from typing import List, Dict


def _sha256_concat(left: str, right: str) -> str:
    """SHA-256(left_bytes ‖ right_bytes) donde left/right son strings hex de 64 chars."""
    data = bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(data).hexdigest()


def build_merkle_root(leaf_hashes: List[str]) -> str:
    """
    Construye el árbol Merkle binario y devuelve la raíz.

    Args:
        leaf_hashes: Lista de hashes SHA-256 en hex (uno por segundo del segmento).

    Returns:
        Merkle root como string hex de 64 caracteres.

    Raises:
        ValueError: Si la lista está vacía.
    """
    if not leaf_hashes:
        raise ValueError("No se puede construir un árbol Merkle vacío")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]

    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # Duplicar último si número impar
        level = [
            _sha256_concat(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ]
    return level[0]


def get_merkle_proof(leaf_hashes: List[str], index: int) -> List[Dict]:
    """
    Devuelve la prueba Merkle (Merkle proof) para la hoja en ``index``.

    La prueba permite verificar que una hoja concreta pertenece al árbol
    sin conocer las demás hojas — idéntico al SPV de Bitcoin.

    Args:
        leaf_hashes: Lista completa de hashes de hojas.
        index: Índice de la hoja que se quiere probar (0 = primer segundo).

    Returns:
        Lista de pasos: [{"hash": str, "side": "left"|"right"}, ...]
        Lista vacía si los parámetros son inválidos.
    """
    if not leaf_hashes or index >= len(leaf_hashes):
        return []

    proof: List[Dict] = []
    level = list(leaf_hashes)
    pos = index

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        if pos % 2 == 0:  # Nodo izquierdo → hermano a la derecha
            sibling = level[pos + 1]
            side = "right"
        else:  # Nodo derecho → hermano a la izquierda
            sibling = level[pos - 1]
            side = "left"

        proof.append({"hash": sibling, "side": side})
        level = [
            _sha256_concat(level[i], level[i + 1]) for i in range(0, len(level), 2)
        ]
        pos //= 2

    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Dict], expected_root: str) -> bool:
    """
    Verifica que ``leaf_hash`` pertenece al árbol con raíz ``expected_root``
    utilizando la prueba de Merkle proporcionada.

    Args:
        leaf_hash:     Hash SHA-256 de la hoja a verificar.
        proof:         Lista de pasos devuelta por :func:`get_merkle_proof`.
        expected_root: Raíz Merkle almacenada (procedente de la cámara original).

    Returns:
        True si la prueba es válida y la hoja pertenece al árbol.
    """
    current = leaf_hash
    for step in proof:
        if step["side"] == "right":
            current = _sha256_concat(current, step["hash"])
        else:
            current = _sha256_concat(step["hash"], current)
    return current == expected_root
