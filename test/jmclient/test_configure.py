'''test configure module.'''

import pytest
from jmclient import load_test_config, jm_single
from jmclient.configure import get_blockchain_interface_instance

pytestmark = pytest.mark.usefixtures("setup_regtest_bitcoind")


def test_attribute_dict():
    from jmclient.configure import AttributeDict
    ad = AttributeDict(foo=1, bar=2, baz={"x":3, "y":4})
    assert ad.foo == 1
    assert ad.bar == 2
    assert ad.baz.x == 3
    assert ad["foo"] == 1


def test_blockchain_sources():
    load_test_config()
    for src in ["dummy"]:
        jm_single().config.set("BLOCKCHAIN", "blockchain_source", src)
        if src == "dummy":
            with pytest.raises(ValueError) as e_info:
                get_blockchain_interface_instance(jm_single().config)
        else:
            get_blockchain_interface_instance(jm_single().config)
    load_test_config()
