# -*- coding: utf-8 -*-

import hashlib
from typing import List, Optional, Tuple, Union, Set, Type

import bitcointx
from bitcointx.core.key import XOnlyPubKey
from bitcointx.core.script import SIGVERSION_TAPROOT, SignatureHashSchnorr
from bitcointx.core import CTxOut
from bitcointx.core.scripteval import (
    CScript, ScriptVerifyFlag_Type, CScriptWitness, VerifyScriptError,
    STANDARD_SCRIPT_VERIFY_FLAGS, UNHANDLED_SCRIPT_VERIFY_FLAGS, EvalScript,
    SCRIPT_VERIFY_CLEANSTACK, script_verify_flags_to_string, _CastToBool,
    ensure_isinstance, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    MAX_SCRIPT_ELEMENT_SIZE, OP_CHECKSIG, OP_EQUALVERIFY, OP_HASH160, OP_DUP)
from bitcointx.core.scripteval import (
    SCRIPT_VERIFY_WITNESS, SCRIPT_VERIFY_P2SH, SIGVERSION_WITNESS_V0)


def VerifyScriptWithTaproot(
    scriptSig: CScript, scriptPubKey: CScript,
    txTo: 'bitcointx.core.CTransaction', inIdx: int,
    flags: Optional[Union[Tuple[ScriptVerifyFlag_Type, ...],
    Set[ScriptVerifyFlag_Type]]] = None,
    amount: int = 0, witness: Optional[CScriptWitness] = None,
    *,
    spent_outputs: Optional[List[CTxOut]] = None
) -> None:
    """Verify a scriptSig satisfies a scriptPubKey

    scriptSig    - Signature

    scriptPubKey - PubKey

    txTo         - Spending transaction

    inIdx        - Index of the transaction input containing scriptSig

    Raises a ValidationError subclass if the validation fails.
    """

    ensure_isinstance(scriptSig, CScript, 'scriptSig')
    if not type(scriptSig) == type(scriptPubKey):  # noqa: exact class check
        raise TypeError(
            "scriptSig and scriptPubKey must be of the same script class")

    script_class = scriptSig.__class__

    if flags is None:
        flags = STANDARD_SCRIPT_VERIFY_FLAGS - UNHANDLED_SCRIPT_VERIFY_FLAGS
    else:
        flags = set(flags)  # might be passed as tuple

    if flags & UNHANDLED_SCRIPT_VERIFY_FLAGS:
        raise VerifyScriptError(
            "some of the flags cannot be handled by current code: {}"
            .format(script_verify_flags_to_string(flags & UNHANDLED_SCRIPT_VERIFY_FLAGS)))

    stack: List[bytes] = []
    EvalScript(stack, scriptSig, txTo, inIdx, flags=flags)
    if SCRIPT_VERIFY_P2SH in flags:
        stackCopy = list(stack)
    EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags)
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    hadWitness = False
    if witness is None:
        witness = CScriptWitness([])

    if SCRIPT_VERIFY_WITNESS in flags and scriptPubKey.is_witness_scriptpubkey():
        hadWitness = True

        if scriptSig:
            raise VerifyScriptError("scriptSig is not empty")

        VerifyWitnessProgramWithTaproot(
            witness,
            scriptPubKey.witness_version(),
            scriptPubKey.witness_program(),
            txTo, inIdx, flags=flags, amount=amount,
            script_class=script_class,
            spent_outputs=spent_outputs)

        # Bypass the cleanstack check at the end. The actual stack is obviously not clean
        # for witness programs.
        stack = stack[:1]

    # Additional validation for spend-to-script-hash transactions
    if SCRIPT_VERIFY_P2SH in flags and scriptPubKey.is_p2sh():
        if not scriptSig.is_push_only():
            raise VerifyScriptError("P2SH scriptSig not is_push_only()")

        # restore stack
        stack = stackCopy

        # stack cannot be empty here, because if it was the
        # P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        # an empty stack and the EvalScript above would return false.
        assert len(stack)

        pubKey2 = script_class(stack.pop())

        EvalScript(stack, pubKey2, txTo, inIdx, flags=flags)

        if not len(stack):
            raise VerifyScriptError("P2SH inner scriptPubKey left an empty stack")

        if not _CastToBool(stack[-1]):
            raise VerifyScriptError("P2SH inner scriptPubKey returned false")

        # P2SH witness program
        if SCRIPT_VERIFY_WITNESS in flags and pubKey2.is_witness_scriptpubkey():
            hadWitness = True

            if scriptSig != script_class([pubKey2]):
                raise VerifyScriptError("scriptSig is not exactly a single push of the redeemScript")

            VerifyWitnessProgramWithTaproot(
                witness,
                pubKey2.witness_version(),
                pubKey2.witness_program(),
                txTo, inIdx, flags=flags, amount=amount,
                script_class=script_class,
                spent_outputs=spent_outputs)

            # Bypass the cleanstack check at the end. The actual stack is obviously not clean
            # for witness programs.
            stack = stack[:1]

    if SCRIPT_VERIFY_CLEANSTACK in flags:
        if SCRIPT_VERIFY_P2SH not in flags:
            raise ValueError(
                'SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_P2SH')

        if len(stack) == 0:
            raise VerifyScriptError("scriptPubKey left an empty stack")
        elif len(stack) != 1:
            raise VerifyScriptError("scriptPubKey left extra items on stack")

    if SCRIPT_VERIFY_WITNESS in flags:
        # We can't check for correct unexpected witness data if P2SH was off, so require
        # that WITNESS implies P2SH. Otherwise, going from WITNESS->P2SH+WITNESS would be
        # possible, which is not a softfork.
        if SCRIPT_VERIFY_P2SH not in flags:
            raise ValueError(
                "SCRIPT_VERIFY_WITNESS requires SCRIPT_VERIFY_P2SH")

        if not hadWitness and witness:
            raise VerifyScriptError("Unexpected witness")


def VerifyWitnessProgramWithTaproot(
    witness: CScriptWitness,
    witversion: int, program: bytes,
    txTo: 'bitcointx.core.CTransaction',
    inIdx: int,
    flags: Set[ScriptVerifyFlag_Type] = set(),
    amount: int = 0,
    script_class: Type[CScript] = CScript,
    *,
    spent_outputs: Optional[List[CTxOut]] = None
) -> None:

    if script_class is None:
        raise ValueError("script class must be specified")

    sigversion = None

    if witversion == 0:
        sigversion = SIGVERSION_WITNESS_V0
        stack = list(witness.stack)
        if len(program) == 32:
            # Version 0 segregated witness program: SHA256(CScript) inside the program,
            # CScript + inputs in witness
            if len(stack) == 0:
                raise VerifyScriptError("witness is empty")

            scriptPubKey = script_class(stack.pop())
            hashScriptPubKey = hashlib.sha256(scriptPubKey).digest()
            if hashScriptPubKey != program:
                raise VerifyScriptError("witness program mismatch")
        elif len(program) == 20:
            # Special case for pay-to-pubkeyhash; signature + pubkey in witness
            if len(stack) != 2:
                raise VerifyScriptError("witness program mismatch")  # 2 items in witness

            scriptPubKey = script_class([OP_DUP, OP_HASH160, program,
                                         OP_EQUALVERIFY, OP_CHECKSIG])
        else:
            raise VerifyScriptError("wrong length for witness program")
    elif witversion == 1:
        sigversion = SIGVERSION_TAPROOT
        stack = list(witness.stack)
        if len(program) == 32:
            if len(stack) == 0:
                raise VerifyScriptError("witness is empty")
            if len(stack) != 1:
                raise VerifyScriptError("only key path spend is supported")
            assert spent_outputs
            sig = stack[0]
            pubkey = XOnlyPubKey(program)
            sighash = SignatureHashSchnorr(txTo, inIdx, spent_outputs)
            if pubkey.verify_schnorr(sighash, sig):
                return
            else:
                raise VerifyScriptError("schnorr signature verify failed")
        else:
            raise VerifyScriptError("wrong length for witness program")
    elif SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in flags:
        raise VerifyScriptError("upgradeable witness program is not accepted")
    else:
        # Higher version witness scripts return true for future softfork compatibility
        return

    assert sigversion is not None

    for i, elt in enumerate(stack):
        if isinstance(elt, int):
            elt_len = len(script_class([elt]))
        else:
            elt_len = len(elt)

        # Disallow stack item size > MAX_SCRIPT_ELEMENT_SIZE in witness stack
        if elt_len > MAX_SCRIPT_ELEMENT_SIZE:
            raise VerifyScriptError(
                "maximum push size exceeded by an item at position {} "
                "on witness stack".format(i))

    EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags, amount=amount, sigversion=sigversion)

    # Scripts inside witness implicitly require cleanstack behaviour
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    elif len(stack) != 1:
        raise VerifyScriptError("scriptPubKey left extra items on stack")

    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    return
