"""TS-A6: token meter and tokenizers."""

from __future__ import annotations

import pytest
from mcp import types

from mcp_shield.metering.meter import Meter, canonical_json
from mcp_shield.metering.tokenizer import CharHeuristicTokenizer, TiktokenTokenizer, make_tokenizer

pytestmark = pytest.mark.anyio


def meter(**kw: object) -> Meter:
    return Meter(CharHeuristicTokenizer(), **kw)  # type: ignore[arg-type]


def test_char_heuristic() -> None:
    t = CharHeuristicTokenizer()
    assert t.count("") == 0 and t.count("abcd") == 1 and t.count("abcde") == 2


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": [1, 2]}) == canonical_json({"a": [1, 2], "b": 1})


async def test_request_tokens_from_arguments() -> None:
    m = meter()
    assert await m.request_tokens(None) == 0
    assert await m.request_tokens({}) == 0
    assert await m.request_tokens({"path": "notes.txt"}) == (len('{"path":"notes.txt"}') + 3) // 4


async def test_structured_content_not_double_counted() -> None:
    m = meter()
    text = types.TextContent(type="text", text='{"result": 5}')
    assert await m.content_tokens([text], {"result": 5}) == await m.content_tokens([text])
    # ...but counted when content is empty
    assert await m.content_tokens([], {"result": 5}) > 0


async def test_images_use_fixed_estimate() -> None:
    m = meter(image_tokens=1234)
    img = types.ImageContent(type="image", data="aGVsbG8=", mime_type="image/png")
    assert await m.content_tokens([img]) == 1234


async def test_embedded_text_resource_counted() -> None:
    m = meter()
    res = types.EmbeddedResource(
        type="resource", resource=types.TextResourceContents(uri="x://a", text="abcd" * 10)
    )
    assert await m.content_tokens([res]) == 10


async def test_definitions_tokens_ignore_meta_and_icons() -> None:
    m = meter()
    tool = types.Tool(name="t", description="d", input_schema={"type": "object"})
    with_meta = tool.model_copy(update={"meta": {"x": "y" * 400}})
    assert await m.definitions_tokens([tool]) == await m.definitions_tokens([with_meta])


async def test_large_payload_counted_off_loop() -> None:
    m = meter(offload_bytes=10)
    assert await m.count_text("a" * 400) == 100


async def test_usage_and_cost() -> None:
    m = meter(input_price_per_million=3.0)
    u = m.usage(request=100, response=900)
    assert u.total_tokens == 1000 and u.est_cost_usd == pytest.approx(0.003)
    assert u.estimated and u.tokenizer == "char:len/4"
    assert meter().usage(request=1).est_cost_usd is None


def test_tiktoken_counts_and_tolerates_special_tokens() -> None:
    try:
        t = TiktokenTokenizer("o200k_base")
    except Exception as e:  # first run needs network to fetch the encoding
        pytest.skip(f"tiktoken encoding unavailable: {e}")
    assert t.name == "tiktoken:o200k_base"
    n = t.count("Every call is audited with its token cost.")
    assert 5 <= n <= 15
    assert t.count("<|endoftext|> is just text here") > 0


def test_make_tokenizer_falls_back() -> None:
    assert make_tokenizer("char").name == "char:len/4"
    assert make_tokenizer("tiktoken", "no-such-encoding").name == "char:len/4"
