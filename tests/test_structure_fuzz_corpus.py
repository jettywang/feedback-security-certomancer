"""Corpus-level invariants for the structure fuzzing mutators.

These tests pin the engineering guarantees the campaign relies on:

* every emitted mutation round-trips through the ASN.1 decoder (the fuzzer
  targets semantic contradictions, not the BER/DER parser itself);
* the corpus is deterministic for a fixed seed;
* the must-refuse registry only references case ids that actually exist, so
  a renamed mutation cannot silently detach an expectation.
"""

import random

from asn1crypto import ocsp, tsp

from tests.structure_fuzz.expectations import (
    OCSP_MUST_REFUSE,
    TSA_MUST_REFUSE,
)
from tests.structure_fuzz.mutators import (
    build_tsa_seed_der,
    mutate_ocsp,
    mutate_tsa,
    OCSP_SEED_FILE,
)
import pathlib

SEED = 20261113


def _ocsp_corpus():
    return list(
        mutate_ocsp(
            pathlib.Path(OCSP_SEED_FILE).read_bytes(), random.Random(SEED)
        )
    )


def _tsa_corpus():
    return list(mutate_tsa(build_tsa_seed_der(), random.Random(SEED)))


def test_every_ocsp_mutation_is_parseable_der():
    for case_id, _description, der in _ocsp_corpus():
        parsed = ocsp.OCSPRequest.load(der)
        assert parsed.dump() == der, (
            f'{case_id} does not re-serialize canonically'
        )


def test_every_tsa_mutation_is_parseable_der():
    for case_id, _description, der in _tsa_corpus():
        parsed = tsp.TimeStampReq.load(der)
        assert parsed.dump() == der, (
            f'{case_id} does not re-serialize canonically'
        )


def test_corpus_is_deterministic_for_a_fixed_seed():
    first = {cid: der for cid, _d, der in _ocsp_corpus()}
    second = {cid: der for cid, _d, der in _ocsp_corpus()}
    assert first == second

    tsa_first = {cid: der for cid, _d, der in _tsa_corpus()}
    tsa_second = {cid: der for cid, _d, der in _tsa_corpus()}
    assert tsa_first == tsa_second


def test_case_ids_are_unique():
    ocsp_ids = [cid for cid, _d, _der in _ocsp_corpus()]
    tsa_ids = [cid for cid, _d, _der in _tsa_corpus()]
    assert len(ocsp_ids) == len(set(ocsp_ids))
    assert len(tsa_ids) == len(set(tsa_ids))


def test_must_refuse_registry_matches_corpus():
    ocsp_ids = {cid for cid, _d, _der in _ocsp_corpus()}
    tsa_ids = {cid for cid, _d, _der in _tsa_corpus()}
    assert OCSP_MUST_REFUSE <= ocsp_ids
    assert TSA_MUST_REFUSE <= tsa_ids


def test_seed_covers_the_required_mutation_axes():
    ocsp_ids = {cid for cid, _d, _der in _ocsp_corpus()}
    tsa_ids = {cid for cid, _d, _der in _tsa_corpus()}

    # length mutations, duplicate extensions, CertID and messageImprint
    assert 'ocsp-certid-hashlen-4096' in ocsp_ids
    assert 'ocsp-duplicate-nonce-2' in ocsp_ids
    assert 'ocsp-duplicate-requests-3' in ocsp_ids
    assert 'tsa-imprint-length-4096' in tsa_ids
    assert 'tsa-duplicate-critical-extension' in tsa_ids
    assert 'tsa-imprint-sha256-oid-sha1-width' in tsa_ids
