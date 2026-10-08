from bemba_context import _load_tsv, find_relevant_pairs


def test_bigc_columns_load_as_english_bemba_pair(tmp_path):
    dataset = tmp_path / "sample.tsv"
    dataset.write_text(
        "pair_id\timage\tsentence_id\timage_id\taudio_id\tsentence\ttranslation\n"
        "1\timage.jpg\t1\t1\taudio.wav\tBemba sentence\tEnglish translation\n",
        encoding="utf-8",
    )

    assert _load_tsv(dataset) == [("English translation", "Bemba sentence")]


def test_bemba_text_can_retrieve_translation_pair():
    pairs = [("Protect your account", "Sungilileni akawunti yenu")]

    assert find_relevant_pairs("Sungilileni akawunti", pairs) == [pairs[0]]