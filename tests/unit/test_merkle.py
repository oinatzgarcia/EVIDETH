"""
Unit tests para app/core/merkle.py

Ejecución:
    pytest tests/unit/test_merkle.py -v

Casos cubiertos:
    1. hash_bytes produce SHA-256 correcto
    2. get_merkle_root es consistente (mismo input = mismo output)
    3. Estructura del árbol con 30 hojas (caso principal EVIDETH)
    4. Todos los proofs válidos con 30 hojas (número par)
    5. Todos los proofs válidos con 17 hojas (número impar, último segmento corto)
    6. Detección de manipulación: cambiar una hoja cambia el root
    7. Proof inválido: hoja manipulada no supera verificación
    8. Caso borde: 1 sola hoja
"""
import hashlib
import pytest
from app.core.merkle import (
    hash_bytes,
    build_merkle_tree,
    get_merkle_root,
    get_merkle_proof,
    verify_merkle_proof,
)


# ── Fixtures ──────────────────────────────────────────

@pytest.fixture
def leaves_30():
    """30 hojas de prueba (segmento completo de 30s)."""
    return [hash_bytes(f"subsegment_{i}".encode()) for i in range(30)]


@pytest.fixture
def leaves_17():
    """17 hojas de prueba (segmento final corto, número impar)."""
    return [hash_bytes(f"subsegment_{i}".encode()) for i in range(17)]


@pytest.fixture
def tree_30(leaves_30):
    return build_merkle_tree(leaves_30)


@pytest.fixture
def tree_17(leaves_17):
    return build_merkle_tree(leaves_17)


# ── Tests ────────────────────────────────────────────

class TestHashBytes:
    def test_produces_valid_sha256(self):
        """hash_bytes debe devolver un hexdigest SHA-256 válido (64 chars)."""
        result = hash_bytes(b"test_video_frame")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_matches_standard_sha256(self):
        """hash_bytes debe coincidir con hashlib.sha256 estándar."""
        data = b"evideth_test"
        expected = hashlib.sha256(data).hexdigest()
        assert hash_bytes(data) == expected

    def test_different_inputs_produce_different_hashes(self):
        """Entradas distintas deben producir hashes distintos."""
        assert hash_bytes(b"frame_1") != hash_bytes(b"frame_2")


class TestGetMerkleRoot:
    def test_consistent_output(self, leaves_30):
        """El mismo input siempre produce el mismo root."""
        root_a = get_merkle_root(leaves_30)
        root_b = get_merkle_root(leaves_30)
        assert root_a == root_b

    def test_root_is_64_chars(self, leaves_30):
        """El root debe ser un SHA-256 hexadecimal de 64 caracteres."""
        root = get_merkle_root(leaves_30)
        assert len(root) == 64

    def test_single_leaf_returns_itself(self):
        """Con una sola hoja, el root es esa misma hoja."""
        leaf = hash_bytes(b"solo_segment")
        assert get_merkle_root([leaf]) == leaf

    def test_empty_raises(self):
        """Lista vacía debe lanzar ValueError."""
        with pytest.raises(ValueError):
            get_merkle_root([])

    def test_tampering_changes_root(self, leaves_30):
        """Manipular cualquier hoja debe cambiar el root (detección de manipulación)."""
        original_root = get_merkle_root(leaves_30)

        for tampered_index in [0, 14, 29]:  # Primero, mitad y último
            tampered = leaves_30[:]
            tampered[tampered_index] = hash_bytes(b"MANIPULATED_FRAME")
            tampered_root = get_merkle_root(tampered)
            assert tampered_root != original_root, (
                f"Manipular hoja {tampered_index} no cambió el root"
            )


class TestBuildMerkleTree:
    def test_tree_structure_30_leaves(self, tree_30):
        """
        Con 30 hojas, el árbol debe tener 6 niveles:
        [30, 16, 8, 4, 2, 1]
        (30 → pad a 30 (par) → 15 + pad a 16 → 8 → 4 → 2 → 1)
        """
        level_sizes = [len(level) for level in tree_30]
        assert level_sizes == [30, 16, 8, 4, 2, 1]

    def test_root_is_last_element(self, leaves_30, tree_30):
        """El root del árbol debe coincidir con get_merkle_root."""
        assert tree_30[-1][0] == get_merkle_root(leaves_30)

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            build_merkle_tree([])


class TestMerkleProof:
    def test_all_proofs_valid_30_leaves(self, leaves_30, tree_30):
        """
        CASO PRINCIPAL: todos los proofs deben ser válidos para 30 hojas.
        Equivale a verificar cada segundo de un segmento completo de 30s.
        """
        root = tree_30[-1][0]
        for i in range(30):
            proof = get_merkle_proof(tree_30, i)
            assert verify_merkle_proof(leaves_30[i], proof, root), (
                f"Proof inválido para hoja {i} (30 hojas)"
            )

    def test_all_proofs_valid_17_leaves(self, leaves_17, tree_17):
        """
        CASO BORDE: todos los proofs deben ser válidos para 17 hojas (impar).
        Incluye la última hoja (index 16) que requiere padding del sibling.
        """
        root = tree_17[-1][0]
        for i in range(17):
            proof = get_merkle_proof(tree_17, i)
            assert verify_merkle_proof(leaves_17[i], proof, root), (
                f"Proof inválido para hoja {i} (17 hojas)"
            )

    def test_tampered_leaf_fails_proof(self, leaves_30, tree_30):
        """
        Una hoja manipulada no debe superar la verificación con el proof original.
        """
        root = tree_30[-1][0]
        proof_for_leaf_14 = get_merkle_proof(tree_30, 14)
        fake_leaf = hash_bytes(b"MANIPULATED_CONTENT")

        assert not verify_merkle_proof(fake_leaf, proof_for_leaf_14, root), (
            "Una hoja manipulada no debe superar verify_merkle_proof"
        )

    def test_wrong_proof_fails(self, leaves_30, tree_30):
        """
        Usar el proof de hoja 0 para verificar la hoja 1 debe fallar.
        """
        root = tree_30[-1][0]
        proof_for_leaf_0 = get_merkle_proof(tree_30, 0)

        assert not verify_merkle_proof(leaves_30[1], proof_for_leaf_0, root), (
            "Proof incorrecto no debe pasar verificación"
        )

    def test_tampered_root_fails(self, leaves_30, tree_30):
        """
        Un root manipulado debe hacer fallar todos los proofs.
        """
        fake_root = hash_bytes(b"FAKE_ROOT")
        proof = get_merkle_proof(tree_30, 0)
        assert not verify_merkle_proof(leaves_30[0], proof, fake_root)
