# app/core/merkle.py
"""
Merkle Tree implementation for EVIDETH.
Provides 1-second sub-segment granularity within each 30s segment.

Each 30s segment is divided into 30 sub-segments of 1s.
The SHA-256 of each sub-segment forms the leaves of the Merkle Tree.
The root is signed with ECDSA P-256, allowing forensic verification
of any specific second without needing the full video.
"""
import hashlib
from typing import List, Dict, Tuple


def hash_bytes(data: bytes) -> str:
    """Calcula el hash SHA-256 de un bloque de bytes."""
    return hashlib.sha256(data).hexdigest()


def build_merkle_tree(leaf_hashes: List[str]) -> List[List[str]]:
    """
    Construye el árbol de Merkle completo desde las hojas hasta el root.
    Cada nivel combina pares de hashes: SHA256(left + right).
    Si el número de hojas es impar, duplica la última hoja.

    Returns:
        Lista de niveles, donde tree[0] son las hojas y tree[-1] es [root].
    """
    if not leaf_hashes:
        raise ValueError("No leaf hashes provided")

    tree = [leaf_hashes[:]]
    current = leaf_hashes[:]

    while len(current) > 1:
        if len(current) % 2 != 0:
            current.append(current[-1])  # Duplica el último nodo si impar
        next_level = []
        for i in range(0, len(current), 2):
            combined = current[i] + current[i + 1]
            next_level.append(hashlib.sha256(combined.encode()).hexdigest())
        tree.append(next_level)
        current = next_level

    return tree


def get_merkle_root(leaf_hashes: List[str]) -> str:
    """
    Calcula solo el root del árbol de Merkle.
    Caso especial: si solo hay una hoja, el root es esa misma hoja.
    """
    if not leaf_hashes:
        raise ValueError("No leaf hashes provided")
    if len(leaf_hashes) == 1:
        return leaf_hashes[0]
    return build_merkle_tree(leaf_hashes)[-1][0]


def get_merkle_proof(tree: List[List[str]], leaf_index: int) -> List[Dict]:
    """
    Genera el proof de Merkle para una hoja específica.
    El proof es la lista de hashes hermanos necesarios para reconstruir el root.

    Args:
        tree:       Árbol completo generado por build_merkle_tree().
        leaf_index: Índice de la hoja (sub-segmento) a verificar (0..N-1).

    Returns:
        Lista de {hash, position} donde position es 'left' o 'right'.
    """
    proof = []
    index = leaf_index

    for level in tree[:-1]:  # Todos los niveles excepto el root
        sibling_index = index + 1 if index % 2 == 0 else index - 1
        if sibling_index < len(level):
            proof.append({
                "hash":     level[sibling_index],
                "position": "right" if index % 2 == 0 else "left"
            })
        index //= 2

    return proof


def verify_merkle_proof(leaf_hash: str, proof: List[Dict], root: str) -> bool:
    """
    Verifica que una hoja pertenece al árbol dado su Merkle proof.
    No necesita el árbol completo ni el video original.

    Args:
        leaf_hash: SHA-256 del sub-segmento a verificar.
        proof:     Lista de hashes hermanos (generada por get_merkle_proof).
        root:      Merkle root almacenado en BD (firmado con ECDSA).

    Returns:
        True si el sub-segmento es íntegro, False si fue manipulado.
    """
    current = leaf_hash
    for step in proof:
        if step["position"] == "right":
            combined = current + step["hash"]
        else:
            combined = step["hash"] + current
        current = hashlib.sha256(combined.encode()).hexdigest()
    return current == root
